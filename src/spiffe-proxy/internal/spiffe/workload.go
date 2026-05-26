package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	aimtls "github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mtls"
)

// WorkloadIdentity manages SPIFFE workload identity and certificates via the Workload API.
type WorkloadIdentity struct {
	source      *workloadapi.X509Source
	trustDomain spiffeid.TrustDomain
	spiffeID    spiffeid.ID
	mu          sync.RWMutex
}

// NewWorkloadIdentity connects to the SPIRE Agent's Workload API and obtains an X509-SVID.
func NewWorkloadIdentity(ctx context.Context, socketPath string) (*WorkloadIdentity, error) {
	source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socketPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509 source: %w", err)
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("failed to get X509 SVID: %w", err)
	}

	log.Printf("[SPIFFE] Obtained SVID: %s", svid.ID.String())
	log.Printf("[SPIFFE] Certificate expires: %s", svid.Certificates[0].NotAfter)

	return &WorkloadIdentity{
		source:      source,
		trustDomain: svid.ID.TrustDomain(),
		spiffeID:    svid.ID,
	}, nil
}

// GetClientTLSConfig returns mTLS client config that validates the server's SPIFFE ID.
func (w *WorkloadIdentity) GetClientTLSConfig(allowedIDs []spiffeid.ID) *tls.Config {
	authorizer := tlsconfig.AuthorizeOneOf(allowedIDs...)
	return tlsconfig.MTLSClientConfig(w.source, w.source, authorizer)
}

// GetServerTLSConfig returns mTLS server config that validates the client's SPIFFE ID.
func (w *WorkloadIdentity) GetServerTLSConfig(allowedIDs []spiffeid.ID) *tls.Config {
	authorizer := tlsconfig.AuthorizeOneOf(allowedIDs...)
	return tlsconfig.MTLSServerConfig(w.source, w.source, authorizer)
}

// GetDynamicServerTLSConfig returns mTLS server config using a DynamicAuthorizer
// whose allow list can be updated at runtime via the management API.
// This replaces the static AuthorizeOneOf for the progressive hardening demo.
func (w *WorkloadIdentity) GetDynamicServerTLSConfig(auth *aimtls.DynamicAuthorizer) *tls.Config {
	// Create a custom authorizer that wraps our dynamic allow list.
	// The go-spiffe Authorizer type is func(spiffeid.ID, [][]*x509.Certificate) error.
	authorizer := func(actual spiffeid.ID, _ [][]*x509.Certificate) error {
		return auth.Authorize(actual)
	}
	return tlsconfig.MTLSServerConfig(w.source, w.source, authorizer)
}

// GetSVID returns the current X509 SVID certificate.
func (w *WorkloadIdentity) GetSVID() (*x509.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	svid, err := w.source.GetX509SVID()
	if err != nil {
		return nil, err
	}
	return svid.Certificates[0], nil
}

// SpiffeID returns the workload's SPIFFE ID.
func (w *WorkloadIdentity) SpiffeID() spiffeid.ID {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.spiffeID
}

// TrustDomain returns the trust domain.
func (w *WorkloadIdentity) TrustDomain() spiffeid.TrustDomain {
	return w.trustDomain
}

// Close releases the X509Source.
func (w *WorkloadIdentity) Close() error {
	return w.source.Close()
}
