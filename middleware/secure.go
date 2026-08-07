package middleware

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

type (
	// SecureConfig defines the config for Secure middleware.
	SecureConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper Skipper

		// XSSProtection provides protection against cross-site scripting attack (XSS)
		// by setting the `X-XSS-Protection` header.
		// Optional. Default value "1; mode=block".
		XSSProtection string `yaml:"xss_protection"` 

		// ContentTypeNosniff provides protection against overriding Content-Type
		// header by setting the `X-Content-Type-Options` header.
		// Optional. Default value "nosniff".
		ContentTypeNosniff string `yaml:"content_type_nosniff"` 

		// XFrameOptions can be used to indicate whether or not a browser should
		// be allowed to render a page in a <frame>, <iframe> or <object> .
		// Optional. Default value "SAMEORIGIN".
		// Possible values: "SAMEORIGIN", "DENY", "ALLOW-FROM uri".
		XFrameOptions string `yaml:"x_frame_options"` 

		// HSTSMaxAge sets the Strict-Transport-Security header to indicate how
		// long (in seconds) the browser should remember that this site is only
		// to be accessed using HTTPS.
		// Optional. Default value 0.
		HSTSMaxAge int `yaml:"hsts_max_age"` 

		// HSTSExcludeSubdomains excludes subdomains from Strict-Transport-Security.
		// Optional. Default value false.
		HSTSExcludeSubdomains bool `yaml:"hsts_exclude_subdomains"` 

		// ContentSecurityPolicy sets the Content-Security-Policy header providing
		// security against cross-site scripting (XSS), clickjacking and other code
		// injection attacks resulting from execution of malicious content in the
		// trusted web page context.
		// Optional. Default value "".
		ContentSecurityPolicy string `yaml:"content_security_policy"` 

		// CSPReportOnly sets the Content-Security-Policy-Report-Only header.
		// Optional. Default value false.
		CSPReportOnly bool `yaml:"csp_report_only"` 

		// HSTSPreloadEnabled sets the preload flag on the Strict-Transport-Security header.
		// Optional. Default value false.
		HSTSPreloadEnabled bool `yaml:"hsts_preload_enabled"` 

		// ReferrerPolicy sets the Referrer-Policy header providing security against
		// leaking sensitive information to other sites.
		// Optional. Default value "".
		ReferrerPolicy string `yaml:"referrer_policy"` 

		// HTTPSRedirect redirects HTTP requests to HTTPS.
		// Optional. Default value false.
		HTTPSRedirect bool `yaml:"https_redirect"` 

		// HTTPSHost redirects HTTP requests to HTTPS on the given host.
		// Optional. Default value "".
		HTTPSHost string `yaml:"https_host"` 

		// HTTPSRedirectSkipper defines a function to skip HTTPS redirect.
		// Optional.
		HTTPSRedirectSkipper Skipper `yaml:"https_redirect_skipper"` 
	}
)

var (
	// DefaultSecureConfig is the default Secure middleware config.
	DefaultSecureConfig = SecureConfig{
		Skipper:            DefaultSkipper,
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "SAMEORIGIN",
	}
)

// Secure returns a Secure middleware.
// See: https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
func Secure() echo.MiddlewareFunc {
	return SecureWithConfig(DefaultSecureConfig)
}

// SecureWithConfig returns a Secure middleware with config.
// See: `Secure()`
func SecureWithConfig(config SecureConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultSecureConfig.Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { 
			if config.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()

			isSecure := req.TLS != nil ||
				req.Header.Get(echo.HeaderXForwardedProto) == "https" ||
				req.Header.Get("X-Forwarded-Scheme") == "https" ||
				req.Header.Get("Front-End-Https") == "on"

			if config.HTTPSRedirect {
				if config.HTTPSRedirectSkipper == nil || !config.HTTPSRedirectSkipper(c) {
					if !isSecure {
						url := req.URL
						url.Scheme = "https"
						if config.HTTPSHost != "" {
							url.Host = config.HTTPSHost
						} else {
							url.Host = req.Host
						}

						code := http.StatusMovedPermanently // Default 301
						if req.Method != http.MethodGet && req.Method != http.MethodHead {
							code = http.StatusPermanentRedirect // 308 to preserve method and body
						}
						return c.Redirect(code, url.String())
					}
				}
			}

			if config.XSSProtection != "" {
				res.Header().Set(echo.HeaderXXSSProtection, config.XSSProtection)
			}
			if config.ContentTypeNosniff != "" {
				res.Header().Set(echo.HeaderXContentTypeOptions, config.ContentTypeNosniff)
			}
			if config.XFrameOptions != "" {
				res.Header().Set(echo.HeaderXFrameOptions, config.XFrameOptions)
			}
			if isSecure && config.HSTSMaxAge != 0 {
				subdomains := ""
				if !config.HSTSExcludeSubdomains {
					subdomains = "; includeSubDomains"
				}
				preload := ""
				if config.HSTSPreloadEnabled {
					preload = "; preload"
				}
				res.Header().Set(echo.HeaderStrictTransportSecurity, fmt.Sprintf("max-age=%d%s%s", config.HSTSMaxAge, subdomains, preload))
			}
			if config.ContentSecurityPolicy != "" {
				if config.CSPReportOnly {
					res.Header().Set(echo.HeaderContentSecurityPolicyReportOnly, config.ContentSecurityPolicy)
				} else {
					res.Header().Set(echo.HeaderContentSecurityPolicy, config.ContentSecurityPolicy)
				}
			}
			if config.ReferrerPolicy != "" {
				res.Header().Set(echo.HeaderReferrerPolicy, config.ReferrerPolicy)
			}
			return next(c)
		}
	}
}