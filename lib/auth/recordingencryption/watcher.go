// Teleport
// Copyright (C) 2025 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package recordingencryption

import (
	"context"
	"log/slog"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	recordingencryptionv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/recordingencryption/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/retryutils"
)

// Resolver resolves RecordingEncryption state and passes the result to a postProcessFn callback to be called
// before any locks are released.
type Resolver interface {
	ResolveRecordingEncryption(ctx context.Context) (*recordingencryptionv1.RecordingEncryption, error)
}

// WatchConfig captures required dependencies for building a RecordingEncryption watcher that
// automatically resolves state.
type WatchConfig struct {
	Events   types.Events
	Resolver Resolver
	Logger   *slog.Logger
}

// A Watcher watches for changes to the RecordingEncryption resource and resolves the state for the calling
// auth server.
type Watcher struct {
	events   types.Events
	resolver Resolver
	logger   *slog.Logger
}

// NewWatcher returns a new Watcher.
func NewWatcher(cfg WatchConfig) (*Watcher, error) {
	switch {
	case cfg.Events == nil:
		return nil, trace.BadParameter("events is required")
	case cfg.Resolver == nil:
		return nil, trace.BadParameter("recording encryption resolver is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.With(teleport.ComponentKey, "encryption-watcher")
	}

	return &Watcher{
		events:   cfg.Events,
		resolver: cfg.Resolver,
		logger:   cfg.Logger,
	}, nil
}

// Watch creates a watcher responsible for responding to changes in the RecordingEncryption resource.
// This is how auth servers cooperate and ensure there are accessible wrapped keys for each unique keystore
// configuration in a cluster.
func (w *Watcher) Run(ctx context.Context) (err error) {
	// shouldRetryAfterJitterFn waits at most 5 seconds and returns a bool specifying whether or not
	// execution should continue
	shouldRetryAfterJitterFn := func() bool {
		select {
		case <-time.After(retryutils.SeventhJitter(time.Second * 5)):
			return true
		case <-ctx.Done():
			return false
		}
	}

	defer func() {
		w.logger.InfoContext(ctx, "stopping encryption watcher", "error", err)
	}()

	for {
		watch, err := w.events.NewWatcher(ctx, types.Watch{
			Name: "recording_encryption_watcher",
			Kinds: []types.WatchKind{
				{
					Kind: types.KindRecordingEncryption,
				},
			},
		})
		if err != nil {
			w.logger.ErrorContext(ctx, "failed to create watcher, retrying", "error", err)
			if !shouldRetryAfterJitterFn() {
				return nil
			}
			continue
		}
		defer watch.Close()

	HandleEvents:
		for {
			if _, err := w.resolver.ResolveRecordingEncryption(ctx); err != nil {
				w.logger.ErrorContext(ctx, "failure while resolving recording encryption state", "error", err)
				if !shouldRetryAfterJitterFn() {
					return nil
				}
				continue

			}

			select {
			case ev := <-watch.Events():
				if ev.Type != types.OpPut {
					continue
				}
			case <-watch.Done():
				if err := watch.Error(); err == nil {
					return nil
				}

				w.logger.ErrorContext(ctx, "watcher failed, retrying", "error", err)
				if !shouldRetryAfterJitterFn() {
					return nil
				}
				break HandleEvents
			case <-ctx.Done():
				return nil
			}
		}
	}
}
