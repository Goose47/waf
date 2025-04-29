// Package waf provides functions to interact with WAF service.
package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	gen "github.com/Goose47/wafpb/gen/go/waf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ConfigOption func(*WAF)

func WithHostPort(host string, port int) ConfigOption {
	return func(config *WAF) {
		config.host = host
		config.port = port
	}
}

// WAF contains methods to interact with WAF service API.
type WAF struct {
	client gen.WAFClient
	host   string
	port   int
}

func New(opts ...ConfigOption) (*WAF, error) {
	waf := &WAF{}

	for _, opt := range opts {
		opt(waf)
	}

	gRPCAddress := net.JoinHostPort(waf.host, strconv.Itoa(waf.port))
	cc, err := grpc.NewClient(gRPCAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to grpc server: %v", err)
	}

	client := gen.NewWAFClient(cc)
	waf.client = client

	return waf, nil
}

// Analyze extracts request parameters, json payload if present and sends request to WAF service.
func (waf *WAF) Analyze(
	ctx context.Context,
	r *http.Request,
) (bool, error) {
	clientIP, clientPort, _ := net.SplitHostPort(r.RemoteAddr)
	serverIP, serverPort, _ := net.SplitHostPort(r.Host)

	// Extract headers
	headers := make([]*gen.AnalyzeRequest_HTTPParam, 0, len(r.Header))
	for key, values := range r.Header {
		headers = append(headers, &gen.AnalyzeRequest_HTTPParam{
			Key:   key,
			Value: strings.Join(values, ", "),
		})
	}

	// Extract query parameters
	queryParams := make([]*gen.AnalyzeRequest_HTTPParam, 0, len(r.URL.Query()))
	for key, values := range r.URL.Query() {
		queryParams = append(queryParams, &gen.AnalyzeRequest_HTTPParam{
			Key:   key,
			Value: strings.Join(values, ", "),
		})
	}

	// Extract body parameters (assuming JSON)
	bodyParams := make([]*gen.AnalyzeRequest_HTTPParam, 0)
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)

		// Restore the body
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if err == nil && len(bodyBytes) > 0 {
			bodyMap := make(map[string]any)
			_ = json.Unmarshal(bodyBytes, &bodyMap)
			for key, value := range bodyMap {
				bodyParams = append(bodyParams, &gen.AnalyzeRequest_HTTPParam{Key: key, Value: fmt.Sprintf("%v", value)})
			}
		}
	}

	req := &gen.AnalyzeRequest{
		Timestamp:   timestamppb.New(time.Now()),
		ClientIp:    clientIP,
		ClientPort:  clientPort,
		ServerIp:    serverIP,
		ServerPort:  serverPort,
		Uri:         r.RequestURI,
		Method:      r.Method,
		Proto:       r.Proto,
		Headers:     headers,
		QueryParams: queryParams,
		BodyParams:  bodyParams,
	}

	res, err := waf.client.Analyze(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to analyze request: %v", err)
	}

	//todo threshold
	//todo rate limit
	return res.AttackProbability == 1, nil
}
