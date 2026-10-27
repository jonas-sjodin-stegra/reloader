package hashivault

import (
	"context"
	"fmt"
	"testing"

	"github.com/external-secrets/reloader/internal/events"
	"github.com/external-secrets/reloader/internal/listener/schema"
	"github.com/go-logr/logr"
)

func TestProcessKVWriteEvents(t *testing.T) {
	for _, operation := range []string{"create", "update", "read"} {
		for _, version := range []string{"v1", "v2"} {
			t.Run(operation+"/"+version, func(t *testing.T) {
				path := "secret/apps/example/api-key"
				if version == "v2" {
					path = "secret/data/apps/example/api-key"
				}
				eventChan := make(chan events.SecretRotationEvent, 1)
				listener := &HashicorpVault{
					context:   context.Background(),
					eventChan: eventChan,
					logger:    logr.Discard(),
				}
				listener.processFn([]byte(fmt.Sprintf(`{
					"type": "response",
					"request": {"operation": %q, "path": %q},
					"response": {"mount_type": "kv", "mount_point": "secret/"}
				}`, operation, path)))

				if operation == "read" {
					if len(eventChan) != 0 {
						t.Fatal("read operation emitted a rotation event")
					}
					return
				}
				select {
				case event := <-eventChan:
					if event.SecretIdentifier != "apps/example/api-key" {
						t.Errorf("unexpected secret identifier: %q", event.SecretIdentifier)
					}
					if event.TriggerSource != schema.HASHICORP_VAULT {
						t.Errorf("unexpected trigger source: %q", event.TriggerSource)
					}
					if event.RotationTimestamp == "" {
						t.Error("missing rotation timestamp")
					}
				default:
					t.Fatal("write operation did not emit a rotation event")
				}
			})
		}
	}
}
