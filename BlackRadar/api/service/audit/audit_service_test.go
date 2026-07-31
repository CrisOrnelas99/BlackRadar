// Package audit verifies audit-event service behavior.
package audit

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

func TestServiceRecordsSafeEvent(t *testing.T) {
	repository := &fakeRepository{}
	service := NewService(repository)
	context := newAuditContext(t)
	actorID := "00000000-0000-4000-8000-000000000001"

	err := service.Record(context, EventInput{ActorUserID: &actorID, Action: "asset.create", ResourceType: "asset", Result: ResultSucceeded})
	if err != nil {
		t.Fatalf("expected audit event to be recorded, got %v", err)
	}
	if repository.event.RequestID != "request-123" || repository.event.Action != "asset.create" || repository.event.ActorUserID == nil || *repository.event.ActorUserID != actorID {
		t.Fatalf("unexpected persisted event: %#v", repository.event)
	}
}

func TestServiceRejectsUnsafeDetails(t *testing.T) {
	service := NewService(&fakeRepository{})
	err := service.Record(newAuditContext(t), EventInput{Action: "asset.create", ResourceType: "asset", Result: ResultSucceeded, Details: "password=secret\nsecond-line"})
	if err != ErrInvalidEvent {
		t.Fatalf("expected invalid event error, got %v", err)
	}
}

type fakeRepository struct{ event model.AuditEvent }

func (r *fakeRepository) Create(_ *appcontext.GinContext, event model.AuditEvent) error {
	r.event = event
	return nil
}

func newAuditContext(t *testing.T) *appcontext.GinContext {
	t.Helper()
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	return appcontext.NewGinContext(context, "request-123", slog.New(slog.NewTextHandler(io.Discard, nil)))
}
