//! Product-neutral capability contracts and in-process dispatch.
//!
//! Products supply handlers and policy. Herald never retries a handler after an
//! ambiguous outcome and does not turn cancellation into proof of rollback.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::{mpsc, watch};

/// A future returned by an injected asynchronous port.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Whether a product can establish support for a capability.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum Support {
    Supported,
    Unsupported,
    Unknown,
}

/// The semantic category of a capability.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum Kind {
    Operation,
    Query,
    Subscription,
}

/// A stable capability identifier and its schema version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityId {
    pub name: String,
    pub version: u32,
}

/// Schemas and presentation-independent semantics supplied by the product.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Contract {
    pub id: CapabilityId,
    pub kind: Kind,
    pub input_schema: Value,
    pub output_schema: Value,
    pub error_schema: Value,
    pub event_schema: Value,
    pub required_capabilities: Vec<String>,
    pub confirmation_required: bool,
    pub support: Support,
}

/// A request carries an identity reference from a trusted transport boundary. The product authorizer must verify its provenance; caller-controlled identity and confirmation fields are not proof of authentication or consent.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Request {
    pub capability: CapabilityId,
    pub identity: String,
    pub input: Value,
    pub confirmed: bool,
}

/// A product error, including an explicitly unknown mutation outcome.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub enum Outcome {
    Success(Value),
    Error(Value),
    Unknown(Value),
}

/// Failures in registration or dispatch, separate from product outcomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchError {
    DuplicateCapability,
    InvalidSchema(String),
    NotFound,
    Denied,
    Unsupported,
    SupportUnknown,
    ConfirmationRequired,
    InvalidInput(String),
    /// The handler ran, but its response violated the contract. The operation may have taken effect and must not be retried automatically.
    InvalidOutput(String),
    /// The handler ran, but its error violated the contract. The operation may have taken effect and must not be retried automatically.
    InvalidError(String),
    CancelledBeforeDispatch,
    WrongCapabilityKind,
    InvalidEvent(String),
    SubscriptionSource(Value),
    /// The caller dropped an in-flight handler; its side effects are unknown.
    OutcomeLost,
}

/// Cooperative cancellation. A handler decides how cancellation affects its work.
#[derive(Clone)]
pub struct Cancellation {
    receiver: watch::Receiver<bool>,
}

/// Creates a cancellation handle and its associated signal.
pub fn cancellation() -> (watch::Sender<bool>, Cancellation) {
    let (sender, receiver) = watch::channel(false);
    (sender, Cancellation { receiver })
}

impl Cancellation {
    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Waits for a cancellation request. Sender closure without a request is not cancellation.
    pub async fn cancelled(&mut self) {
        while !self.is_cancelled() {
            if self.receiver.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Product-provided confirmation verification. A caller-supplied claim is not itself proof of consent.
pub trait Confirmer: Send + Sync {
    fn confirm<'a>(&'a self, request: &'a Request, contract: &'a Contract) -> PortFuture<'a, bool>;
}

/// Product-provided authorisation, evaluated for every dispatch.
pub trait Authorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: &'a Request,
        contract: &'a Contract,
    ) -> PortFuture<'a, bool>;
}

/// A product-owned handler. It must represent uncertain outcomes explicitly.
pub trait Handler: Send + Sync {
    fn invoke<'a>(
        &'a self,
        request: &'a Request,
        cancellation: Cancellation,
    ) -> PortFuture<'a, Outcome>;
}

/// A product-owned subscription source. The bounded receiver preserves producer backpressure.
pub trait SubscriptionHandler: Send + Sync {
    fn subscribe<'a>(
        &'a self,
        request: &'a Request,
        cancellation: Cancellation,
    ) -> PortFuture<'a, mpsc::Receiver<Result<Value, Value>>>;
}

/// A subscription validates each event as it is received.
pub struct Subscription {
    receiver: mpsc::Receiver<Result<Value, Value>>,
    validator: Arc<jsonschema::Validator>,
}

impl Subscription {
    /// Receives the next event, returning an error when its schema is violated.
    pub async fn recv(&mut self) -> Option<Result<Value, DispatchError>> {
        let event = match self.receiver.recv().await? {
            Ok(event) => event,
            Err(error) => return Some(Err(DispatchError::SubscriptionSource(error))),
        };
        Some(
            self.validator
                .validate(&event)
                .map(|()| event.clone())
                .map_err(|e| DispatchError::InvalidEvent(e.to_string())),
        )
    }
}

/// Clock injected by the composition root.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// Product-owned observer receives dispatch outcomes and timestamps.
pub trait Observer: Send + Sync {
    fn finished(&self, request: &Request, at: u64, result: &Result<Outcome, DispatchError>);
    /// Records whether a subscription was opened or denied.
    fn subscription_opened(&self, request: &Request, at: u64, result: &Result<(), DispatchError>);
}

struct InFlight<'a> {
    observer: &'a dyn Observer,
    clock: &'a dyn Clock,
    request: &'a Request,
    completed: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.observer.finished(
                self.request,
                self.clock.now(),
                &Err(DispatchError::OutcomeLost),
            );
        }
    }
}

struct Entry {
    contract: Contract,
    handler: Option<Arc<dyn Handler>>,
    subscription: Option<Arc<dyn SubscriptionHandler>>,
    input: jsonschema::Validator,
    output: jsonschema::Validator,
    error: jsonschema::Validator,
    event: Arc<jsonschema::Validator>,
}

/// A registry and dispatcher composed entirely in the calling process.
pub struct Dispatcher {
    entries: BTreeMap<CapabilityId, Entry>,
    authorizer: Arc<dyn Authorizer>,
    confirmer: Arc<dyn Confirmer>,
    clock: Arc<dyn Clock>,
    observer: Arc<dyn Observer>,
}

impl Dispatcher {
    /// Creates an empty dispatcher with product-owned policy and observability.
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        confirmer: Arc<dyn Confirmer>,
        clock: Arc<dyn Clock>,
        observer: Arc<dyn Observer>,
    ) -> Self {
        Self {
            entries: BTreeMap::new(),
            authorizer,
            confirmer,
            clock,
            observer,
        }
    }

    /// Registers a capability. Invalid schemas and duplicate identifiers are rejected.
    pub fn register(
        &mut self,
        contract: Contract,
        handler: Arc<dyn Handler>,
    ) -> Result<(), DispatchError> {
        if contract.kind == Kind::Subscription {
            return Err(DispatchError::WrongCapabilityKind);
        }
        self.register_inner(contract, Some(handler), None)
    }

    /// Registers a product-owned subscription source.
    pub fn register_subscription(
        &mut self,
        contract: Contract,
        handler: Arc<dyn SubscriptionHandler>,
    ) -> Result<(), DispatchError> {
        if contract.kind != Kind::Subscription {
            return Err(DispatchError::WrongCapabilityKind);
        }
        self.register_inner(contract, None, Some(handler))
    }

    fn register_inner(
        &mut self,
        contract: Contract,
        handler: Option<Arc<dyn Handler>>,
        subscription: Option<Arc<dyn SubscriptionHandler>>,
    ) -> Result<(), DispatchError> {
        if self.entries.contains_key(&contract.id) {
            return Err(DispatchError::DuplicateCapability);
        }
        let compile = |schema: &Value| {
            jsonschema::validator_for(schema)
                .map_err(|e| DispatchError::InvalidSchema(e.to_string()))
        };
        let input = compile(&contract.input_schema)?;
        let output = compile(&contract.output_schema)?;
        let error = compile(&contract.error_schema)?;
        let event = compile(&contract.event_schema)?;
        self.entries.insert(
            contract.id.clone(),
            Entry {
                contract,
                handler,
                subscription,
                input,
                output,
                error,
                event: Arc::new(event),
            },
        );
        Ok(())
    }

    /// Returns registered contracts. Exposure policy must be applied by the caller.
    pub fn contracts(&self) -> impl Iterator<Item = &Contract> {
        self.entries.values().map(|entry| &entry.contract)
    }

    /// Validates an event against a registered subscription's event schema.
    pub fn validate_event(&self, id: &CapabilityId, event: &Value) -> Result<(), DispatchError> {
        let entry = self.entries.get(id).ok_or(DispatchError::NotFound)?;
        if entry.contract.kind != Kind::Subscription {
            return Err(DispatchError::WrongCapabilityKind);
        }
        entry
            .event
            .validate(event)
            .map_err(|e| DispatchError::InvalidEvent(e.to_string()))
    }

    /// Authorises and opens a product-owned subscription.
    pub async fn subscribe(
        &self,
        request: Request,
        cancellation: Cancellation,
    ) -> Result<Subscription, DispatchError> {
        let result = self.subscribe_inner(&request, cancellation).await;
        let audit = result.as_ref().map(|_| ()).map_err(Clone::clone);
        self.observer
            .subscription_opened(&request, self.clock.now(), &audit);
        result
    }

    async fn subscribe_inner(
        &self,
        request: &Request,
        cancellation: Cancellation,
    ) -> Result<Subscription, DispatchError> {
        let entry = self
            .entries
            .get(&request.capability)
            .ok_or(DispatchError::NotFound)?;
        let handler = entry
            .subscription
            .as_ref()
            .ok_or(DispatchError::WrongCapabilityKind)?;
        if !self.authorizer.authorize(request, &entry.contract).await {
            return Err(DispatchError::Denied);
        }
        match entry.contract.support {
            Support::Supported => {}
            Support::Unsupported => return Err(DispatchError::Unsupported),
            Support::Unknown => return Err(DispatchError::SupportUnknown),
        }
        if entry.contract.confirmation_required
            && !self.confirmer.confirm(request, &entry.contract).await
        {
            return Err(DispatchError::ConfirmationRequired);
        }
        entry
            .input
            .validate(&request.input)
            .map_err(|e| DispatchError::InvalidInput(e.to_string()))?;
        if cancellation.is_cancelled() {
            return Err(DispatchError::CancelledBeforeDispatch);
        }
        let receiver = handler.subscribe(request, cancellation).await;
        Ok(Subscription {
            receiver,
            validator: entry.event.clone(),
        })
    }

    /// Starts an in-process operation independently of the caller's wait. Dropping the returned handle detaches the task; it does not cancel the operation. Runtime or process loss can still leave its outcome unknown.
    pub fn start(
        self: &Arc<Self>,
        request: Request,
        cancellation: Cancellation,
    ) -> tokio::task::JoinHandle<Result<Outcome, DispatchError>> {
        let dispatcher = Arc::clone(self);
        tokio::spawn(async move { dispatcher.dispatch(request, cancellation).await })
    }

    /// Validates and authorises a request before invoking its handler once.
    pub async fn dispatch(
        &self,
        request: Request,
        cancellation: Cancellation,
    ) -> Result<Outcome, DispatchError> {
        let result = self.dispatch_inner(&request, cancellation).await;
        self.observer.finished(&request, self.clock.now(), &result);
        result
    }

    async fn dispatch_inner(
        &self,
        request: &Request,
        cancellation: Cancellation,
    ) -> Result<Outcome, DispatchError> {
        let entry = self
            .entries
            .get(&request.capability)
            .ok_or(DispatchError::NotFound)?;
        if !self.authorizer.authorize(request, &entry.contract).await {
            return Err(DispatchError::Denied);
        }
        match entry.contract.support {
            Support::Supported => {}
            Support::Unsupported => return Err(DispatchError::Unsupported),
            Support::Unknown => return Err(DispatchError::SupportUnknown),
        }
        if entry.contract.confirmation_required
            && !self.confirmer.confirm(request, &entry.contract).await
        {
            return Err(DispatchError::ConfirmationRequired);
        }
        entry
            .input
            .validate(&request.input)
            .map_err(|e| DispatchError::InvalidInput(e.to_string()))?;
        if cancellation.is_cancelled() {
            return Err(DispatchError::CancelledBeforeDispatch);
        }
        let handler = entry
            .handler
            .as_ref()
            .ok_or(DispatchError::WrongCapabilityKind)?;
        let mut in_flight = InFlight {
            observer: self.observer.as_ref(),
            clock: self.clock.as_ref(),
            request,
            completed: false,
        };
        let outcome = handler.invoke(request, cancellation).await;
        in_flight.completed = true;
        match &outcome {
            Outcome::Success(value) => entry
                .output
                .validate(value)
                .map_err(|e| DispatchError::InvalidOutput(e.to_string()))?,
            Outcome::Error(value) | Outcome::Unknown(value) => entry
                .error
                .validate(value)
                .map_err(|e| DispatchError::InvalidError(e.to_string()))?,
        }
        Ok(outcome)
    }
}
