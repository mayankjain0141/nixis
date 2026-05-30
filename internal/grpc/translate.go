// SPDX-License-Identifier: MIT
package grpc

import (
	"encoding/json"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

func translateRequest(envoyReq *authv3.CheckRequest) nixis.CheckRequest {
	attrs := envoyReq.GetAttributes()
	http := attrs.GetRequest().GetHttp()

	toolName := http.GetMethod() + " " + http.GetPath()
	if toolName == " " {
		toolName = "unknown"
	}

	headers := http.GetHeaders()
	sessionID := headers["x-nixis-session"]
	if sessionID == "" {
		sessionID = headers["x-request-id"]
	}
	if sessionID == "" {
		sessionID = "grpc-ext-authz"
	}

	argsJSON, _ := json.Marshal(map[string]any{
		"method":  http.GetMethod(),
		"path":    http.GetPath(),
		"headers": headers,
	})

	return nixis.CheckRequest{
		Tool:      toolName,
		Args:      argsJSON,
		SessionID: sessionID,
	}
}

func translateResponse(resp nixis.CheckResponse) *authv3.CheckResponse {
	switch resp.Decision.Action {
	case nixis.ActionAllow:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{},
			},
		}
	case nixis.ActionAudit:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "x-nixis-audited", Value: "true"}},
					},
				},
			},
		}
	case nixis.ActionRequireApproval:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Headers: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "x-nixis-approval-required", Value: "true"}},
					},
				},
			},
		}
	case nixis.ActionDeny:
		return denyResponse(resp.Decision.Reason)
	default:
		return denyResponse(resp.Decision.Reason)
	}
}

func denyResponse(reason string) *authv3.CheckResponse {
	if len(reason) > 256 {
		reason = reason[:256] + "..."
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   reason,
			},
		},
	}
}
