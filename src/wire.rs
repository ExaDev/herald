//! Typed errors for every adapter. A [`WireError`] is what a client sees: a stable code, a message
//! and nothing that reveals product internals.

use crate::DispatchError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A stable, machine-readable error code. Adapters map it to their own status or error shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The capability or operation does not exist, or is not exposed on this surface.
    NotFound,
    /// The caller is not authorised.
    Denied,
    /// The capability is known not to be supported.
    Unsupported,
    /// Whether the capability is supported is not known.
    SupportUnknown,
    /// The product's confirmation was not given.
    ConfirmationRequired,
    /// The input broke the capability's schema.
    InvalidInput,
    /// The idempotency key was already used for a different request.
    KeyConflict,
    /// The request was cancelled before it ran.
    Cancelled,
    /// The server could not take the request now, for example because it is at its concurrency
    /// limit or its authentication backend failed. Nothing ran, and a retry is safe.
    Unavailable,
    /// The request ran past its deadline and was dropped. A synchronous call's handler was told to
    /// stop, so for an operation the outcome may be unknown: follow it by id.
    TimedOut,
    /// The request was interrupted before the handler started, so nothing ran.
    Interrupted,
    /// The handler may have run and its outcome is unknown. This is the same condition a handler
    /// reports with an unknown outcome (a result flagged `uncertain`), reached because the caller
    /// dropped the request or the handler panicked. A client treats the two alike: the effect may
    /// have happened, so follow the operation by id before retrying.
    OutcomeLost,
    /// The handler ran but its response broke the capability's contract. The effect may have
    /// happened, as for `OutcomeLost`; the response is withheld because it cannot be trusted.
    ContractViolation,
    /// Storage failed.
    Store,
    /// The request itself was malformed (a missing key, a bad cursor).
    BadRequest,
    /// The request body was larger than the adapter accepts.
    TooLarge,
    /// The request was not in a media type the adapter accepts.
    UnsupportedMedia,
    /// The same key is still running. Follow the operation by id instead of submitting again.
    InProgress,
    /// A product's source for a subscription failed; `detail` is its error object.
    SourceFailed,
    /// The adapter could not authenticate the caller.
    Unauthenticated,
    /// The request came from a host or origin the adapter does not serve.
    ForbiddenOrigin,
}

/// An error as an adapter reports it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    /// Product data safe to show the caller, such as a subscription source's error object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// The most of a validator's text a response carries. The text can quote the offending input, so
/// without a bound a response would be as large as the request that caused it.
pub const MAX_DETAIL_BYTES: usize = 1024;

fn truncated(text: &str) -> &str {
    let mut end = text.len().min(MAX_DETAIL_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }
}

impl From<&DispatchError> for WireError {
    fn from(error: &DispatchError) -> Self {
        use DispatchError as D;
        let (code, message) = match error {
            D::NotFound => (ErrorCode::NotFound, "no such capability"),
            D::WrongCapabilityKind => (ErrorCode::BadRequest, "the capability is not of that kind"),
            D::Denied => (ErrorCode::Denied, "not authorised"),
            D::Unsupported => (ErrorCode::Unsupported, "the capability is not supported"),
            D::SupportUnknown => (
                ErrorCode::SupportUnknown,
                "support for the capability is not known",
            ),
            D::ConfirmationRequired => {
                (ErrorCode::ConfirmationRequired, "confirmation is required")
            }
            // The message names the caller's own input against the published schema, so it is safe to return.
            D::InvalidInput(detail) => {
                return Self {
                    code: ErrorCode::InvalidInput,
                    message: "the input does not match the capability's schema".into(),
                    detail: Some(Value::String(truncated(detail).to_owned())),
                };
            }
            D::SubscriptionSource(source) => {
                return Self {
                    code: ErrorCode::SourceFailed,
                    message: "the source failed".into(),
                    detail: Some(source.clone()),
                };
            }
            D::KeyConflict => (
                ErrorCode::KeyConflict,
                "the idempotency key was used for a different request",
            ),
            D::CancelledBeforeDispatch => (ErrorCode::Cancelled, "cancelled before it ran"),
            D::InterruptedBeforeDispatch => (ErrorCode::Interrupted, "interrupted before it ran"),
            D::OutcomeLost => (ErrorCode::OutcomeLost, "the outcome is unknown"),
            D::InvalidOutput(_)
            | D::InvalidError(_)
            | D::InvalidEvent(_)
            | D::InvalidSchema(_)
            | D::InvalidName(_)
            | D::DuplicateCapability => (
                ErrorCode::ContractViolation,
                "the handler's response broke its contract",
            ),
            D::Store(_) => (ErrorCode::Store, "storage failed"),
        };
        Self::new(code, message)
    }
}
