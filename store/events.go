package store

import (
	"context"

	policyengine "github.com/conductera/policy-engine"
)

// EventStore lists bounded namespace-ordered local state events. Mutation
// methods on the other capabilities must append their corresponding event in
// the same atomic commit. Expired retained cursors return CURSOR_EXPIRED.
type EventStore interface {
	ListEvents(context.Context, policyengine.ListEventsRequest) (policyengine.ListEventsResponse, error)
}
