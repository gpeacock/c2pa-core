//! Layer 1: spec-agnostic JUMBF box parsing (ISO/IEC 19566-5).
//!
//! Produces a tree of [`Node`]s whose payloads are borrowed spans into the input
//! buffer. This layer knows nothing about C2PA semantics — see [`crate::store`].

use alloc::vec::Vec;

use crate::box_reader::BoxReader;
use crate::error::Error;
use crate::format::{
    BOX_ID_LEN, BOX_JUMB, BOX_JUMD, BOX_SALT, HDR_BASE, HDR_XL, SIGNATURE_HASH_LEN, TOGGLE_ID,
    TOGGLE_LABEL, TOGGLE_PRIVATE, TOGGLE_SIGNATURE,
};
use crate::limits::Limits;
use crate::uuids::{classify, ContentType};

/// A description box (`jumd`): identifies a superbox's type and label.
#[derive(Debug, Clone, Copy)]
pub struct Description<'a> {
    /// The full span of the `jumd` box, including its original header.
    pub raw: &'a [u8],
    /// The 16-byte content-type UUID (the authoritative type discriminator).
    pub uuid: [u8; 16],
    /// The raw toggle byte.
    pub toggles: u8,
    /// The label, if the label toggle was set.
    pub label: Option<&'a str>,
    /// The salt bytes from the private `c2sh` box, if present.
    pub salt: Option<&'a [u8]>,
}

impl Description<'_> {
    /// The classified content type of this box.
    pub fn content_type(&self) -> ContentType {
        classify(&self.uuid)
    }
}

/// A leaf content box (anything that is not a `jumb` superbox), e.g. `cbor`,
/// `json`, or embedded data. Its `data` borrows from the input.
#[derive(Debug, Clone, Copy)]
pub struct ContentBox<'a> {
    /// The full span of this box, including its original header.
    pub raw: &'a [u8],
    /// The 4-byte box type.
    pub tbox: [u8; 4],
    /// The box payload (everything after the header).
    pub data: &'a [u8],
}

/// A JUMBF superbox (`jumb`): a description box followed by child nodes.
#[derive(Debug)]
pub struct SuperBox<'a> {
    /// The description box.
    pub description: Description<'a>,
    /// Child boxes, in order.
    pub children: Vec<Node<'a>>,
    /// The full span of this box (header included) in the input.
    pub raw: &'a [u8],
    /// The box payload (bytes after the `jumb` header). Exposed via
    /// [`SuperBox::payload`].
    payload: &'a [u8],
}

/// A node in the box tree: either a nested superbox or a leaf content box.
#[derive(Debug)]
pub enum Node<'a> {
    /// A nested superbox.
    Super(SuperBox<'a>),
    /// A leaf content box.
    Content(ContentBox<'a>),
}

/// Running counter used to enforce the global box budget.
struct Budget {
    boxes: usize,
    limit: usize,
}

impl Budget {
    fn charge(&mut self) -> Result<(), Error> {
        self.boxes = self.boxes.checked_add(1).ok_or(Error::LengthOverflow)?;
        if self.boxes > self.limit {
            return Err(Error::BoxBudgetExceeded);
        }
        Ok(())
    }
}

/// A raw box: its type, its payload, and its full span.
struct RawBox<'a> {
    tbox: [u8; 4],
    payload: &'a [u8],
    total: &'a [u8],
}

/// Parse a single box starting at the cursor's current position.
fn parse_box<'a>(r: &mut BoxReader<'a>) -> Result<RawBox<'a>, Error> {
    let start = r.position();
    let lbox = r.u32()?;
    let tbox: [u8; 4] = r.take(4)?.try_into().map_err(|_| Error::UnexpectedEof)?;

    let (total_len, header_len) = match lbox {
        1 => {
            let xl = r.u64()?;
            (
                usize::try_from(xl).map_err(|_| Error::LengthOverflow)?,
                HDR_XL,
            )
        }
        0 => {
            // Length 0 means "to the end of the enclosing region".
            let total = HDR_BASE
                .checked_add(r.remaining())
                .ok_or(Error::LengthOverflow)?;
            (total, HDR_BASE)
        }
        n => (n as usize, HDR_BASE),
    };

    let payload_len = total_len
        .checked_sub(header_len)
        .ok_or(Error::InvalidBoxLength)?;
    let payload = r.take(payload_len)?;
    let end = start.checked_add(total_len).ok_or(Error::LengthOverflow)?;
    let total = r.slice(start, end)?;

    Ok(RawBox {
        tbox,
        payload,
        total,
    })
}

fn parse_description(raw: RawBox<'_>) -> Result<Description<'_>, Error> {
    let mut r = BoxReader::new(raw.payload);
    let uuid = r.array16()?;
    let toggles = r.u8()?;

    // Fields must be consumed in spec order to reach the private (salt) box.
    let label = if toggles & TOGGLE_LABEL != 0 {
        Some(read_label(&mut r)?)
    } else {
        None
    };
    if toggles & TOGGLE_ID != 0 {
        let _ = r.take(BOX_ID_LEN)?;
    }
    if toggles & TOGGLE_SIGNATURE != 0 {
        let _ = r.take(SIGNATURE_HASH_LEN)?;
    }
    let salt = if toggles & TOGGLE_PRIVATE != 0 {
        let private = parse_box(&mut r)?;
        if private.tbox == BOX_SALT {
            Some(private.payload)
        } else {
            // A private box of another type is valid JUMBF; it just isn't a salt.
            None
        }
    } else {
        None
    };

    Ok(Description {
        raw: raw.total,
        uuid,
        toggles,
        label,
        salt,
    })
}

/// Read a `NUL`-terminated UTF-8 label, advancing past the terminator so that
/// any following fields (id, signature, private box) can still be read.
fn read_label<'a>(r: &mut BoxReader<'a>) -> Result<&'a str, Error> {
    let bytes = r.read_cstr()?;
    core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
}

fn parse_superbox<'a>(
    raw: RawBox<'a>,
    depth: usize,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<SuperBox<'a>, Error> {
    let mut r = BoxReader::new(raw.payload);

    let first = parse_box(&mut r)?;
    if first.tbox != BOX_JUMD {
        return Err(Error::MissingDescription);
    }
    let description = parse_description(first)?;

    let mut children = Vec::new();
    let mut count: usize = 0;
    while !r.is_empty() {
        count = count.checked_add(1).ok_or(Error::LengthOverflow)?;
        if count > limits.max_boxes_per_super {
            return Err(Error::TooManyBoxes);
        }
        let child = parse_box(&mut r)?;
        children.push(parse_node(child, depth, limits, budget)?);
    }

    Ok(SuperBox {
        description,
        children,
        raw: raw.total,
        payload: raw.payload,
    })
}

fn parse_node<'a>(
    raw: RawBox<'a>,
    depth: usize,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Node<'a>, Error> {
    budget.charge()?;
    if raw.tbox == BOX_JUMB {
        let next = depth.checked_add(1).ok_or(Error::LengthOverflow)?;
        if next > limits.max_depth {
            return Err(Error::DepthExceeded);
        }
        Ok(Node::Super(parse_superbox(raw, next, limits, budget)?))
    } else {
        Ok(Node::Content(ContentBox {
            raw: raw.total,
            tbox: raw.tbox,
            data: raw.payload,
        }))
    }
}

/// Parse the top-level superbox from `bytes`.
pub(crate) fn parse_root<'a>(bytes: &'a [u8], limits: &Limits) -> Result<SuperBox<'a>, Error> {
    if bytes.len() > limits.max_total_len {
        return Err(Error::InputTooLarge);
    }
    if limits.max_depth == 0 {
        return Err(Error::DepthExceeded);
    }

    let mut r = BoxReader::new(bytes);
    let raw = parse_box(&mut r)?;
    if raw.tbox != BOX_JUMB {
        return Err(Error::NotASuperbox);
    }
    if !r.is_empty() {
        return Err(Error::TrailingBytes);
    }

    let mut budget = Budget {
        boxes: 0,
        limit: limits.max_total_boxes,
    };
    budget.charge()?;
    parse_superbox(raw, 1, limits, &mut budget)
}

impl<'a> SuperBox<'a> {
    /// The label of this superbox, if present.
    pub fn label(&self) -> Option<&'a str> {
        self.description.label
    }

    /// The classified content type of this superbox.
    pub fn content_type(&self) -> ContentType {
        self.description.content_type()
    }

    /// The salt bytes carried in this superbox's description, if any.
    pub fn salt(&self) -> Option<&'a [u8]> {
        self.description.salt
    }

    /// The box payload: bytes after the `jumb` header (`jumd` description plus
    /// content boxes) — the span hashed by a C2PA hashed-URI referencing this
    /// box.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The first child content box, if any.
    pub fn first_content(&self) -> Option<&ContentBox<'a>> {
        self.content_children().next()
    }

    /// Find the first child superbox of the given content type.
    pub fn find_super_by_type(&self, content_type: ContentType) -> Option<&SuperBox<'a>> {
        self.super_children()
            .find(|s| s.content_type() == content_type)
    }

    /// Iterate over child superboxes.
    pub fn super_children(&self) -> impl Iterator<Item = &SuperBox<'a>> {
        self.children.iter().filter_map(|n| match n {
            Node::Super(s) => Some(s),
            Node::Content(_) => None,
        })
    }

    /// Iterate over child content boxes.
    pub fn content_children(&self) -> impl Iterator<Item = &ContentBox<'a>> {
        self.children.iter().filter_map(|n| match n {
            Node::Content(c) => Some(c),
            Node::Super(_) => None,
        })
    }

    /// Find the first child superbox with an exactly matching label.
    pub fn find_super(&self, label: &str) -> Option<&SuperBox<'a>> {
        self.super_children().find(|s| s.label() == Some(label))
    }

    /// Find the first child superbox whose label starts with `prefix`.
    pub fn find_super_prefix(&self, prefix: &str) -> Option<&SuperBox<'a>> {
        self.super_children()
            .find(|s| s.label().is_some_and(|l| l.starts_with(prefix)))
    }

    /// Find the first child content box of the given type.
    pub fn find_content(&self, tbox: &[u8; 4]) -> Option<&ContentBox<'a>> {
        self.content_children().find(|c| &c.tbox == tbox)
    }
}
