/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package mcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/gravitational/trace"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/mcputils"
)

// ProxyStdioConnWithAutoReconnectConfig is the config for ProxyStdioConnWithAutoReconnect.
type ProxyStdioConnWithAutoReconnectConfig struct {
	Logger                   *slog.Logger
	ClientStdio              io.ReadWriteCloser
	MakeReconnectUserMessage func(error) string
	DialServer               func(context.Context) (io.ReadWriteCloser, error)

	clientResponseWriter mcputils.MessageWriter
	onServerConnClosed   func()
}

// CheckAndSetDefaults validates the config and sets default values.
func (cfg *ProxyStdioConnWithAutoReconnectConfig) CheckAndSetDefaults() error {
	if cfg.ClientStdio == nil {
		return trace.BadParameter("missing ClientStdio")
	}
	if cfg.DialServer == nil {
		return trace.BadParameter("missing DialServer")
	}
	if cfg.MakeReconnectUserMessage == nil {
		return trace.BadParameter("missing MakeReconnectUserMessage")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.With(
			teleport.ComponentKey,
			teleport.Component(teleport.ComponentMCP, "autoreconnect"),
		)
	}
	if cfg.clientResponseWriter == nil {
		cfg.clientResponseWriter = mcputils.NewStdioMessageWriter(utils.NewSyncWriter(cfg.ClientStdio))
	}
	return nil
}

func ProxyStdioConnWithAutoReconnect(ctx context.Context, cfg ProxyStdioConnWithAutoReconnectConfig) error {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	serverConn, err := newServerConnWithAutoReconnect(ctx, cfg)
	if err != nil {
		return trace.Wrap(err)
	}

	clientRequestReader, err := mcputils.NewStdioMessageReader(mcputils.StdioMessageReaderConfig{
		SourceReadCloser: cfg.ClientStdio,
		ParentContext:    ctx,
		Logger:           cfg.Logger.With("client", "stdin"),
		OnParseError:     mcputils.ReplyParseError(cfg.clientResponseWriter),
		OnNotification: func(ctx context.Context, notification *mcputils.JSONRPCNotification) error {
			// By spec, we should not reply to notifications. Try our best to
			// send a notification with the error message. In practice, only the
			// initialize notification is sent from client after receiving the
			// initialize response so it's unlikely to fail.
			if writeError := serverConn.WriteMessage(ctx, notification); writeError != nil {
				cfg.Logger.WarnContext(ctx, "failed to write notification to server. Notification is dropped.", "error", writeError)
				userMessage := cfg.MakeReconnectUserMessage(writeError)
				errNotification := mcp.Notification{
					Method: "notifications/tsherr",
					Params: mcp.NotificationParams{
						AdditionalFields: map[string]any{
							"error": fmt.Sprintf("Notification %q was dropped. %s", notification.Method, userMessage),
						},
					},
				}
				return trace.Wrap(cfg.clientResponseWriter.WriteMessage(ctx, errNotification))
			}
			return nil
		},
		OnRequest: func(ctx context.Context, request *mcputils.JSONRPCRequest) error {
			if writeError := serverConn.WriteMessage(ctx, request); writeError != nil {
				cfg.Logger.WarnContext(ctx, "failed to write request to server", "error", writeError)
				userMessage := cfg.MakeReconnectUserMessage(writeError)
				errResp := mcp.NewJSONRPCError(request.ID, mcp.INTERNAL_ERROR, userMessage, writeError)
				return trace.Wrap(cfg.clientResponseWriter.WriteMessage(ctx, errResp))
			}
			return nil
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	clientRequestReader.Run(ctx)
	return nil

}

type serverConnWithAutoReconnect struct {
	ProxyStdioConnWithAutoReconnectConfig
	parentCtx context.Context

	mu                  sync.Mutex
	serverRequestWriter mcputils.MessageWriter
	replayOnNextConn    bool
	initRequest         *mcputils.JSONRPCRequest
	initResponse        *mcp.InitializeResult
	initNotification    *mcputils.JSONRPCNotification
}

func newServerConnWithAutoReconnect(parentCtx context.Context, cfg ProxyStdioConnWithAutoReconnectConfig) (*serverConnWithAutoReconnect, error) {
	return &serverConnWithAutoReconnect{
		ProxyStdioConnWithAutoReconnectConfig: cfg,
		parentCtx:                             parentCtx,
	}, nil
}

func (r *serverConnWithAutoReconnect) WriteMessage(ctx context.Context, msg mcp.JSONRPCMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	writer, err := r.getServerRequestWriterLocked(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(writer.WriteMessage(ctx, msg))
}

func (r *serverConnWithAutoReconnect) getServerRequestWriterLocked(ctx context.Context) (mcputils.MessageWriter, error) {
	if r.serverRequestWriter != nil {
		return r.serverRequestWriter, nil
	}

	r.Logger.InfoContext(ctx, "Connecting to server")
	serverConn, err := r.DialServer(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if r.replayOnNextConn {
		if err := r.replayInitializeLocked(ctx, serverConn); err != nil {
			serverConn.Close()
			return nil, trace.Wrap(err)
		}
		r.serverRequestWriter = mcputils.NewStdioMessageWriter(serverConn)
	} else {
		r.serverRequestWriter = mcputils.NewMultiMessageWriter(
			mcputils.MessageWriterFunc(func(ctx context.Context, msg mcp.JSONRPCMessage) error {
				r.cacheMessageLocked(ctx, msg)
				return nil
			}),
			mcputils.NewStdioMessageWriter(serverConn),
		)
		r.replayOnNextConn = true
	}

	// This should never fail as long the correct config is passed in.
	serverResponseReader, err := mcputils.NewStdioMessageReader(mcputils.StdioMessageReaderConfig{
		SourceReadCloser: serverConn,
		ParentContext:    ctx,
		// OnClose is called when server connection is dead.
		OnClose: func() {
			r.Logger.InfoContext(ctx, "Lost server connection, resetting...")
			r.mu.Lock()
			r.serverRequestWriter = nil
			r.mu.Unlock()
			if r.onServerConnClosed != nil {
				r.onServerConnClosed()
			}
		},
		Logger:       r.Logger.With("server", "stdout"),
		OnParseError: mcputils.LogAndIgnoreParseError(r.Logger),
		OnNotification: func(ctx context.Context, notification *mcputils.JSONRPCNotification) error {
			return trace.Wrap(r.clientResponseWriter.WriteMessage(ctx, notification))
		},
		OnResponse: func(ctx context.Context, response *mcputils.JSONRPCResponse) error {
			r.cacheMessageLocked(ctx, response)
			return trace.Wrap(r.clientResponseWriter.WriteMessage(ctx, response))
		},
	})
	if err != nil {
		serverConn.Close()
		return nil, trace.Wrap(err)
	}
	go serverResponseReader.Run(r.parentCtx)
	r.Logger.InfoContext(ctx, "Started a new MCP server connection")
	return r.serverRequestWriter, nil
}

func (r *serverConnWithAutoReconnect) initializedLocked() bool {
	return r.initRequest != nil && r.initResponse != nil && r.initNotification != nil
}

func (r *serverConnWithAutoReconnect) replayInitializeLocked(ctx context.Context, serverConn io.ReadWriter) error {
	if !r.initializedLocked() {
		return trace.Errorf("client has not initialized yet")
	}

	r.Logger.InfoContext(ctx, "Replaying initialize request")
	serverWriter := mcputils.NewStdioMessageWriter(serverConn)
	if err := serverWriter.WriteMessage(ctx, r.initRequest); err != nil {
		return trace.Wrap(err)
	}

	r.Logger.InfoContext(ctx, "Reading and comparing initialize response")
	msg, err := mcputils.ReadOneMessageFromStdioReader(serverConn)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := r.checkReplyResponseLocked(msg); err != nil {
		return trace.Wrap(err)
	}

	r.Logger.InfoContext(ctx, "Replaying initialized notification")
	if err := serverWriter.WriteMessage(ctx, r.initNotification); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (r *serverConnWithAutoReconnect) checkReplyResponseLocked(msg mcp.JSONRPCMessage) error {
	resp, ok := msg.(*mcputils.JSONRPCResponse)
	if !ok {
		return trace.Errorf("expected initialize response, got %T", resp)
	}
	if resp.Error != nil {
		return trace.Errorf("expected initialize result but got error")
	}
	if resp.ID.String() != r.initRequest.ID.String() {
		return trace.CompareFailed("expected initialize response with ID %s, got %s", r.initRequest.ID, resp.ID.String())
	}

	newResult, err := resp.GetInitializeResult()
	if err != nil {
		return trace.Wrap(err)
	}
	if newResult.ServerInfo != r.initResponse.ServerInfo {
		return trace.CompareFailed("server info has changed, expected %s, got %s", r.initResponse.ServerInfo, newResult.ServerInfo)
	}
	return nil
}

// cacheMessageLocked caches client init request and notification.
func (r *serverConnWithAutoReconnect) cacheMessageLocked(ctx context.Context, msg mcp.JSONRPCMessage) {
	if r.initializedLocked() {
		return
	}

	switch m := msg.(type) {
	case *mcputils.JSONRPCRequest:
		if r.initRequest == nil && m.Method == mcp.MethodInitialize {
			r.initRequest = m
			r.Logger.DebugContext(ctx, "Cached msg", "msg", m)
		}
	case *mcputils.JSONRPCNotification:
		if r.initNotification == nil && m.Method == mcputils.MethodNotificationInitialized {
			r.initNotification = m
			r.Logger.DebugContext(ctx, "Cached msg", "msg", m)
		}
	case *mcputils.JSONRPCResponse:
		if r.initResponse == nil && r.initRequest != nil && r.initRequest.ID.String() == m.ID.String() {
			initResponse, err := m.GetInitializeResult()
			if err != nil {
				r.Logger.DebugContext(ctx, "Error parsing init response", "error", err)
			} else {
				r.initResponse = initResponse
				r.Logger.DebugContext(ctx, "Cached msg", "msg", m)
			}
		}
	}
	return
}
