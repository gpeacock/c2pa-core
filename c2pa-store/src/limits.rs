/// Resource limits enforced during parsing to bound work and allocation on
/// adversarial input.
///
/// The defaults are generous enough for real manifests but reject pathological
/// structures (deep nesting, box floods) that would otherwise exhaust memory or
/// the stack. Tighten them for constrained environments via
/// [`ManifestStore::parse_with_limits`](crate::ManifestStore::parse_with_limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum superbox nesting depth. The root superbox is depth 1.
    pub max_depth: usize,
    /// Maximum number of child boxes within a single superbox.
    pub max_boxes_per_super: usize,
    /// Maximum number of boxes across the whole tree (global allocation bound).
    pub max_total_boxes: usize,
    /// Maximum length, in bytes, of the whole input.
    pub max_total_len: usize,
}

impl Limits {
    /// Conservative defaults suitable for general use.
    pub const DEFAULT: Limits = Limits {
        max_depth: 32,
        max_boxes_per_super: 65_536,
        max_total_boxes: 1_048_576,
        max_total_len: 256 * 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}
