//! Manually driven async workflows. Only context requests and checkpoints may
//! suspend: this driver is not an executor for arbitrary I/O futures.
//!
//! A step polls once, returning control at a request or explicit checkpoint.
//! Requests remain available until answered. No task is spawned and dropping
//! the driver drops the suspended future and all of its local variables.
//! Each workflow issues one request at a time; concurrent request futures
//! (`join`/`select`) are not supported by this single-slot bridge.
//! Requests may own processing state (such as a hasher). The host can borrow
//! that state to consume transient input directly, then return ownership with
//! `respond_with`. Input buffers need not be allocated or kept across `.await`.
//!
//! This prototype is intentionally local (`!Send`). It imposes no thread or
//! runtime requirement; a future executor-facing adapter would need real wakers.

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll, Waker};

enum Exchange<Q, R> {
    Idle,
    Request(Q),
    Response(R),
}

pub struct Context<Q, R> {
    exchange: Rc<RefCell<Exchange<Q, R>>>,
}

impl<Q, R> Context<Q, R> {
    pub async fn request(&self, request: Q) -> R {
        let mut request = Some(request);
        poll_fn(|_| {
            let mut exchange = self.exchange.borrow_mut();
            if let Some(request) = request.take() {
                assert!(matches!(*exchange, Exchange::Idle));
                *exchange = Exchange::Request(request);
                return Poll::Pending;
            }
            if matches!(*exchange, Exchange::Response(_)) {
                let Exchange::Response(response) =
                    std::mem::replace(&mut *exchange, Exchange::Idle)
                else {
                    unreachable!();
                };
                Poll::Ready(response)
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Always return control to the host once, even without an I/O request.
    pub async fn checkpoint(&self) {
        let mut yielded = false;
        poll_fn(|_| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                Poll::Pending
            }
        })
        .await
    }
}

pub struct Workflow<Q, R, T> {
    exchange: Rc<RefCell<Exchange<Q, R>>>,
    future: Option<Pin<Box<dyn Future<Output = T>>>>,
    request: Option<Q>,
    output: Option<T>,
}

impl<Q, R, T> Workflow<Q, R, T> {
    pub fn new<F: Future<Output = T> + 'static>(build: impl FnOnce(Context<Q, R>) -> F) -> Self {
        let exchange = Rc::new(RefCell::new(Exchange::Idle));
        let future = build(Context {
            exchange: Rc::clone(&exchange),
        });
        Self {
            exchange,
            future: Some(Box::pin(future)),
            request: None,
            output: None,
        }
    }

    pub fn step(&mut self) {
        if self.request.is_some() {
            return;
        }
        let Some(future) = &mut self.future else {
            return;
        };
        let mut cx = TaskContext::from_waker(Waker::noop());
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => {
                self.output = Some(output);
                self.future = None;
            }
            Poll::Pending => {
                let mut exchange = self.exchange.borrow_mut();
                if matches!(*exchange, Exchange::Request(_)) {
                    let Exchange::Request(request) =
                        std::mem::replace(&mut *exchange, Exchange::Idle)
                    else {
                        unreachable!();
                    };
                    self.request = Some(request);
                }
            }
        }
    }

    pub fn request(&self) -> Option<&Q> {
        self.request.as_ref()
    }

    /// Borrow request-owned state without moving it into a response.
    /// Borrowed input can be processed here without crossing a suspension point.
    pub fn request_mut(&mut self) -> Option<&mut Q> {
        self.request.as_mut()
    }

    /// Return request-owned state to the workflow, without cloning it.
    /// An unsolicited response returns the unapplied function.
    pub fn respond_with<F: FnOnce(Q) -> R>(&mut self, response: F) -> Result<(), F> {
        let Some(request) = self.request.take() else {
            return Err(response);
        };
        *self.exchange.borrow_mut() = Exchange::Response(response(request));
        Ok(())
    }

    /// Reject an unsolicited response without altering the workflow.
    pub fn respond(&mut self, response: R) -> Result<(), R> {
        if self.request.take().is_none() {
            return Err(response);
        }
        *self.exchange.borrow_mut() = Exchange::Response(response);
        Ok(())
    }

    pub fn take_output(&mut self) -> Option<T> {
        self.output.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn borrowed_input_updates_request_state_without_becoming_a_response() {
        let mut workflow = Workflow::new(|cx| async move {
            let total: u64 = cx.request(0u64).await;
            total
        });
        assert!(workflow.respond_with(|n| n).is_err());
        workflow.step();
        {
            let input = [2u8, 3, 4];
            let total = workflow.request_mut().unwrap();
            *total += input.iter().map(|&n| u64::from(n)).sum::<u64>();
        }
        workflow.step();
        assert_eq!(workflow.request(), Some(&9));
        assert!(workflow.respond_with(|n| n).is_ok());
        workflow.step();
        assert_eq!(workflow.take_output(), Some(9));
    }

    #[test]
    fn requests_are_stable_and_checkpoints_suspend_once() {
        let mut workflow = Workflow::new(|cx| async move {
            cx.checkpoint().await;
            let a: u32 = cx.request("first").await;
            cx.checkpoint().await;
            let b = cx.request("second").await;
            a + b
        });
        assert_eq!(workflow.respond(9), Err(9));
        workflow.step();
        assert_eq!(workflow.request(), None);
        assert_eq!(workflow.take_output(), None);
        workflow.step();
        for _ in 0..3 {
            assert_eq!(workflow.request(), Some(&"first"));
            workflow.step();
        }
        workflow.respond(2).unwrap();
        workflow.step();
        assert_eq!(workflow.request(), None);
        assert_eq!(workflow.take_output(), None);
        workflow.step();
        assert_eq!(workflow.request(), Some(&"second"));
        workflow.respond(3).unwrap();
        workflow.step();
        assert_eq!(workflow.take_output(), Some(5));
        workflow.step();
        assert_eq!(workflow.take_output(), None);
        assert_eq!(workflow.respond(9), Err(9));
    }

    #[test]
    fn dropping_a_suspended_workflow_drops_its_locals() {
        struct Guard(Rc<Cell<bool>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let dropped = Rc::new(Cell::new(false));
        let guard = Guard(Rc::clone(&dropped));
        let mut workflow = Workflow::<_, (), ()>::new(|cx| async move {
            let _guard = guard;
            cx.request("waiting").await;
        });
        workflow.step();
        assert!(!dropped.get());
        drop(workflow);
        assert!(dropped.get());
    }

    #[test]
    fn independent_workflows_can_be_interleaved() {
        fn make(offset: u32) -> Workflow<u32, u32, u32> {
            Workflow::new(move |cx| async move {
                let response = cx.request(offset).await;
                cx.checkpoint().await;
                response + offset
            })
        }
        let mut a = make(10);
        let mut b = make(20);
        a.step();
        b.step();
        assert_eq!(a.request(), Some(&10));
        assert_eq!(b.request(), Some(&20));
        b.respond(2).unwrap();
        b.step();
        assert_eq!(a.request(), Some(&10));
        assert_eq!(b.take_output(), None);
        b.step();
        assert_eq!(b.take_output(), Some(22));
        a.respond(1).unwrap();
        a.step();
        a.step();
        assert_eq!(a.take_output(), Some(11));
    }
}
