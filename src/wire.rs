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
    /// The request was interrupted before the handler started, so nothing ran.
    Interrupted,
    /// The handler may have run and its outcome is unknown.
    OutcomeLost,
    /// The handler ran but its response broke the capability's contract.
    ContractViolation,
    /// Storage failed.
    Store,
    /// The request itself was malformed (a missing key, a bad cursor).
    BadRequest,
    /// The adapter could not authenticate the caller.
    Unauthenticated,
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
            D::NotFound | D::WrongCapabilityKind | D::DuplicateCapability => {
                (ErrorCode::NotFound, "no such capability")
            }
            D::Denied => (ErrorCode::Denied, "not authorised"),
            D::Unsupported => (ErrorCode::Unsupported, "the capability is not supported"),
            D::SupportUnknown => (
                ErrorCode::SupportUnknown,
                "support for the capability is not known",
            ),
            D::ConfirmationRequired => {
                (ErrorCode::ConfirmationRequired, "confirmation is required")
            }
            D::InvalidInput(_) => (
                ErrorCode::InvalidInput,
                "the input does not match the capability's schema",
            ),
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
            | D::SubscriptionSource(_)
            | D::InvalidSchema(_) => (
                ErrorCode::ContractViolation,
                "the handler's response broke its contract",
            ),
            D::Store(_) => (ErrorCode::Store, "storage failed"),
        };
        Self::new(code, message)
    }
}
