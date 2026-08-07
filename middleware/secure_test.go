package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestSecure(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	h := Secure()(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	// Default
	h(c)
	assert.Equal(t, "1; mode=block", rec.Header().Get(echo.HeaderXXSSProtection))
	assert.Equal(t, "nosniff", rec.Header().Get(echo.HeaderXContentTypeOptions))
	assert.Equal(t, "SAMEORIGIN", rec.Header().Get(echo.HeaderXFrameOptions))

	// HSTS
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderXForwardedProto, "https")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HSTSMaxAge: 3600,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "max-age=3600; includeSubDomains", rec.Header().Get(echo.HeaderStrictTransportSecurity))

	// HSTS with Preload
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderXForwardedProto, "https")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HSTSMaxAge:         3600,
		HSTSPreloadEnabled: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "max-age=3600; includeSubDomains; preload", rec.Header().Get(echo.HeaderStrictTransportSecurity))

	// HSTS Exclude Subdomains
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderXForwardedProto, "https")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HSTSMaxAge:            3600,
		HSTSExcludeSubdomains: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "max-age=3600", rec.Header().Get(echo.HeaderStrictTransportSecurity))

	// ContentSecurityPolicy
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		ContentSecurityPolicy: "default-src 'self'",
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "default-src 'self'", rec.Header().Get(echo.HeaderContentSecurityPolicy))

	// CSPReportOnly
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		ContentSecurityPolicy: "default-src 'self'",
		CSPReportOnly:         true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "default-src 'self'", rec.Header().Get(echo.HeaderContentSecurityPolicyReportOnly))

	// ReferrerPolicy
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		ReferrerPolicy: "same-origin",
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, "same-origin", rec.Header().Get(echo.HeaderReferrerPolicy))

	// HTTPSRedirect
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Equal(t, "https://example.com/", rec.Header().Get(echo.HeaderLocation))

	// HTTPSRedirect with HTTPSHost
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
		HTTPSHost:     "www.example.com",
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Equal(t, "https://www.example.com/", rec.Header().Get(echo.HeaderLocation))

	// HTTPSRedirect with TLS
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusOK, rec.Code)

	// HTTPSRedirect with X-Forwarded-Scheme
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Scheme", "https")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusOK, rec.Code)

	// HTTPSRedirect with Front-End-Https
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Front-End-Https", "on")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusOK, rec.Code)

	// HTTPSRedirect with POST method (should redirect with 308)
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusPermanentRedirect, rec.Code)
	assert.Equal(t, "https://example.com/", rec.Header().Get(echo.HeaderLocation))

	// HTTPSRedirect with HTTPSRedirectSkipper
	req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetPath("/api/test")
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
		HTTPSRedirectSkipper: func(c echo.Context) bool {
			return c.Path() == "/api/test"
		},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Skipper bypassing secure middleware
	req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetPath("/api/test")
	h = SecureWithConfig(SecureConfig{
		HTTPSRedirect: true,
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/api/test"
		},
	})(func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	h(c)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get(echo.HeaderXXSSProtection))
}