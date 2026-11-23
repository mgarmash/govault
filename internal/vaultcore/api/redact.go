package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
)

// transportError is a safe diagnostic for a failed request: the
// operation, the URL without credentials or query, and the kind of
// failure. Nested errors are never formatted, as their text can quote a
// signed URL, such as a redirect's Location.
type transportError struct {
	op, url, kind string
	err           error
}

func (e *transportError) Error() string {
	if e.url == "" {
		return e.kind
	}
	return e.op + " " + e.url + ": " + e.kind
}

// Unwrap keeps errors.Is and errors.As working for callers.
func (e *transportError) Unwrap() error { return e.err }

// redactURLError replaces err with a transportError.
func redactURLError(err error) error {
	te := &transportError{kind: transportKind(err), err: err}
	var ue *url.Error
	if errors.As(err, &ue) {
		te.op, te.url = ue.Op, RedactURL(ue.URL)
	}
	return te
}

func transportKind(err error) string {
	var dns *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "the request timed out"
	case errors.Is(err, context.Canceled):
		return "the request was cancelled"
	case errors.As(err, &dns):
		return "the server name did not resolve"
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority), errors.As(err, &hostname):
		return "the server's certificate is not trusted"
	case errors.Is(err, ErrRedirectRefused):
		return "the server redirected the request elsewhere"
	case errors.As(err, &opErr):
		return "the connection failed"
	}
	return "the request failed"
}

// RedactURL is raw without user information, query or fragment.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparsable URL)"
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return u.String()
}
