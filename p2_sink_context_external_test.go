package policyengine_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	policyengine "github.com/cadrena/policy-engine"
)

func completedDecisionForSink(t *testing.T) policyengine.CompletedDecisionEvent {
	t.Helper()
	event, err := policyengine.NewCompletedDecisionEvent(policyengine.CompletedDecisionEventInput{
		Decision: policyengine.DecisionAllow, ReasonCode: "GRAPH_ALLOWED",
		RevisionID: testRevisionID(t), CompletedAt: time.Date(2026, time.July, 29, 15, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func assertSinkContextDelivery(t *testing.T, delivery policyengine.DecisionDelivery, reason string) {
	t.Helper()
	if delivery.Status() != policyengine.DecisionDeliveryFailed || delivery.ReasonCode() != reason {
		t.Fatalf("delivery = %v/%q, want failed/%q", delivery.Status(), delivery.ReasonCode(), reason)
	}
	if strings.Contains(delivery.ReasonCode(), "sink-secret") {
		t.Fatalf("delivery leaked sink detail %q", delivery.ReasonCode())
	}
}

func TestDecisionSinkMapsCancellationAndDeadlineBeforeAndAfterCall(t *testing.T) {
	t.Parallel()
	event := completedDecisionForSink(t)

	t.Run("canceled before call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var calls atomic.Int32
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			calls.Add(1)
			return policyengine.DecisionDelivery{}
		}), event)
		assertSinkContextDelivery(t, delivery, "CANCELED")
		if calls.Load() != 0 {
			t.Fatalf("sink calls = %d, want 0", calls.Load())
		}
	})

	t.Run("deadline before call", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		var calls atomic.Int32
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			calls.Add(1)
			return policyengine.DecisionDelivery{}
		}), event)
		assertSinkContextDelivery(t, delivery, "DEADLINE_EXCEEDED")
		if calls.Load() != 0 {
			t.Fatalf("sink calls = %d, want 0", calls.Load())
		}
	})

	t.Run("canceled while sink returns valid detail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			cancel()
			value, err := policyengine.NewDecisionDelivery(policyengine.DecisionDeliveryFailed, "sink-secret-detail")
			if err != nil {
				t.Fatal(err)
			}
			return value
		}), event)
		assertSinkContextDelivery(t, delivery, "CANCELED")
	})

	t.Run("canceled while sink returns zero output", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(context.Context, policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			cancel()
			return policyengine.DecisionDelivery{}
		}), event)
		assertSinkContextDelivery(t, delivery, "CANCELED")
	})

	t.Run("deadline while sink returns valid detail", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(ctx context.Context, _ policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			<-ctx.Done()
			value, err := policyengine.NewDecisionDelivery(policyengine.DecisionDeliveryFailed, "sink-secret-detail")
			if err != nil {
				t.Fatal(err)
			}
			return value
		}), event)
		assertSinkContextDelivery(t, delivery, "DEADLINE_EXCEEDED")
	})

	t.Run("deadline while sink returns zero output", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		delivery := policyengine.DeliverDecisionEvent(ctx, sinkFunc(func(ctx context.Context, _ policyengine.CompletedDecisionEvent) policyengine.DecisionDelivery {
			<-ctx.Done()
			return policyengine.DecisionDelivery{}
		}), event)
		assertSinkContextDelivery(t, delivery, "DEADLINE_EXCEEDED")
	})
}
