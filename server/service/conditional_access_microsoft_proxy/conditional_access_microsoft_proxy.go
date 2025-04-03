package conditional_access_microsoft_proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttp"
)

type Proxy struct {
	uri    string
	apiKey string

	c *http.Client
}

func New(uri string, apiKey string) (*Proxy, error) {
	if _, err := url.Parse(uri); err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	return &Proxy{
		uri:    uri,
		apiKey: apiKey,
		c:      fleethttp.NewClient(),
	}, nil
}

type createRequest struct {
	TenantID string `json:"entraTenantId"`
}
type CreateResponse struct {
	TenantID string `json:"entra_tenant_id"`
	Secret   string `json:"server_secret"`
}

func (p *Proxy) Create(ctx context.Context, tenantID string) (*CreateResponse, error) {
	var createResponse CreateResponse
	if err := p.post(
		"/api/v1/microsoft-compliance-partner",
		createRequest{TenantID: tenantID},
		&createResponse,
	); err != nil {
		return nil, fmt.Errorf("create failed: %w", err)
	}
	return &createResponse, nil
}

type GetResponse struct {
	TenantID        string  `json:"entra_tenant_id"`
	SetupDone       bool    `json:"setup_done"`
	AdminConsented  bool    `json:"admin_consented"`
	AdminConsentURL string  `json:"admin_consent_url"`
	SetupError      *string `json:"setup_error"`
}

func (p *Proxy) Get(ctx context.Context, tenantID string, secret string) (*GetResponse, error) {
	return &GetResponse{}, nil
}

type DeleteResponse struct {
	Error string `json:"error"`
}

func (p *Proxy) Delete(ctx context.Context, tenantID string, secret string) (*DeleteResponse, error) {
	return &DeleteResponse{}, nil
}

type SetComplianceStatusResponse struct {
	MessageID string `json:"message_id"`
}

func (p *Proxy) SetComplianceStatus(
	ctx context.Context,
	tenantID string, secret string,
	deviceID, deviceName, osName, osVersion string,
	compliant bool,
	lastCheckInTime time.Time,
) (*SetComplianceStatusResponse, error) {
	return &SetComplianceStatusResponse{}, nil
}

type GetMessageStatusResponse struct {
	MessageID string  `json:"message_id"`
	Status    string  `json:"status"`
	Detail    *string `json:"detail"`
}

func (p *Proxy) GetMessageStatus(
	ctx context.Context,
	tenantID string, secret string,
	messageID string,
) (*GetMessageStatusResponse, error) {
	return &GetMessageStatusResponse{}, nil
}

func (p *Proxy) post(path string, request interface{}, response interface{}) error {
	b, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	resp, err := p.c.Post(p.uri+path, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("post request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if err := json.Unmarshal(body, response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}
