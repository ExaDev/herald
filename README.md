# Herald

Herald is a product-neutral framework for declaring application capabilities once and exposing them through multiple interfaces. The in-process Rust registry and dispatcher are under development; remote runtimes and interface adapters described below remain design goals.

## Purpose

Applications own their operations, business rules, permissions and user workflows. Herald supplies reusable contracts and adapters so those operations can be invoked consistently from MCP, APIs, command-line interfaces, terminal interfaces, web applications and native applications. Products remain independently usable and do not need a shared daemon or database.

## Architecture

A product registers versioned operations, queries and subscriptions with input, output, error and event schemas, semantic metadata and handlers. The in-process dispatcher validates and routes requests through product-supplied authorisation, confirmation, clock and observability ports. Identity and confirmation claims require verification by those product-supplied ports; a caller-provided value is not proof. Future adapters will translate the same contracts into interfaces, while product policy stays in the product.

The intended runtime supports in-process composition and remote invocation through transport contracts, with persistence supplied through an asynchronous storage contract. The in-process dispatcher alone records nothing. The `runtime` module adds durable operations in front of it: caller-scoped idempotency keys map to stable operation IDs, a retry with fresh authorisation replays the recorded outcome without running the handler, a key reused for another payload is rejected, an operation accepted but never completed reads as unknown after a restart, and clients follow an operation's events from their own cursor. Storage is a product-supplied port, and a transport carries serialisable envelopes. Cancellation is cooperative; a lost outcome must not be treated as an automatic failure or a safe retry.

Durable operation events, ephemeral media and input streams, and inference streams have different ordering, backpressure and recovery requirements. Adapters must preserve those semantics rather than force them into one replay model. Existing protocol-compatible inference endpoints remain product-owned.

## Interfaces

- **MCP:** expose explicitly selected capabilities as tools and other appropriate protocol primitives, respecting product authorisation and transport semantics.
- **API:** expose versioned contracts over a transport with authenticated dispatch and typed errors; enable client generation without requiring one particular network protocol.
- **CLI:** derive baseline commands, arguments, help and machine-readable output from capability metadata while allowing product-designed workflows and confirmations.
- **TUI:** offer reusable terminal lifecycle, operation discovery and progress primitives; products own specialised interaction and layouts.
- **Web GUI:** provide client contracts and reusable presentation primitives for capabilities, forms and operation state; products own navigation, accessibility and workflows.
- **Native GUI:** use the same language-neutral contracts from native clients. A web-based shell is optional, not a requirement.

Schemas describe data, not a complete user experience or a security policy. Presentation metadata can describe labels, sensitive fields and confirmation requirements, but cannot infer safe defaults, authorisation or the meaning of an operation. Specialised views such as live video, editors and model streaming remain product-specific.

## Boundaries

Herald is not a fleet scheduler, model server, device driver, agent runtime or shared product UI. Applications provide their own policy, storage, operation handlers and domain models. Identity and transport libraries can be composed at the edge; the framework does not replace them or require every consumer to use the same one.

The initial implementation should be validated against both an in-process device application and a durable multi-client service. Contract and adapter tests must cover equivalent semantic outcomes, denial, validation, cancellation and ambiguous mutations across the surfaces that expose each operation.
