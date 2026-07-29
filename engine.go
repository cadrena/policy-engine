package policyengine

import "context"

// PolicyService manages local immutable policy revisions and optional slots.
type PolicyService interface {
	Publish(context.Context, Caller, PublishRequest) (PublishResponse, error)
	GetRevision(context.Context, Caller, GetRevisionRequest) (GetRevisionResponse, error)
	ListRevisions(context.Context, Caller, ListRevisionsRequest) (ListRevisionsResponse, error)
	Activate(context.Context, Caller, ActivateRequest) (ActivateResponse, error)
	Resolve(context.Context, Caller, ResolveRequest) (ResolveResponse, error)
	ListActivationHistory(context.Context, Caller, ListActivationHistoryRequest) (ListActivationHistoryResponse, error)
}

// AuthorizationService evaluates policy decisions against pinned local state.
type AuthorizationService interface {
	Check(context.Context, Caller, CheckRequest) (CheckResponse, error)
	BatchCheck(context.Context, Caller, BatchCheckRequest) (BatchCheckResponse, error)
	Explain(context.Context, Caller, ExplainRequest) (ExplainResponse, error)
}

// DataService atomically mutates persistent authorization data.
type DataService interface {
	GetDataGeneration(context.Context, Caller, GetDataGenerationRequest) (GetDataGenerationResponse, error)
	WriteData(context.Context, Caller, WriteDataRequest) (WriteDataResponse, error)
}

// EventsService reads bounded local state events.
type EventsService interface {
	ListEvents(context.Context, Caller, ListEventsRequest) (ListEventsResponse, error)
}

// SystemService reports detailed local component and readiness status.
type SystemService interface {
	Status(context.Context, Caller, StatusRequest) (StatusResponse, error)
}

// Engine composes every transport-neutral embedded service at the module root.
type Engine interface {
	PolicyService
	AuthorizationService
	DataService
	EventsService
	SystemService
}
