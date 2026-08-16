package middleware

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// redactedQueryParams name query parameters whose values must never reach a log
// line.
//
// gin.Logger logs the full request target, query string included. Display
// tokens travel in the query string because EventSource cannot set a header, so
// the stock logger would write a working credential to stdout on every request
// from every screen — and from there into whatever aggregates the container's
// logs, where it would sit indefinitely with a far wider audience than the
// database ever had.
var redactedQueryParams = map[string]bool{
	"display_token": true,
	"token":         true,
	"access_token":  true,
	"api_key":       true,
}

const redactedPlaceholder = "REDACTED"

// RequestLogger logs each request with sensitive query parameters removed.
func RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		return fmt.Sprintf("[certpilot] %s | %3d | %13v | %15s | %-7s %s\n",
			p.TimeStamp.Format(time.RFC3339),
			p.StatusCode,
			p.Latency,
			p.ClientIP,
			p.Method,
			RedactQueryString(p.Path),
		)
	})
}

// RedactQueryString replaces the values of sensitive query parameters in a
// request target.
//
// A target that will not parse is returned with its query string dropped
// entirely rather than passed through: if the value cannot be inspected, it
// cannot be shown to be safe.
func RedactQueryString(target string) string {
	path, query, found := strings.Cut(target, "?")
	if !found {
		return target
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return path + "?" + redactedPlaceholder
	}

	redacted := false
	for key, vals := range values {
		if !redactedQueryParams[strings.ToLower(key)] {
			continue
		}
		for i := range vals {
			vals[i] = redactedPlaceholder
		}
		redacted = true
	}
	if !redacted {
		return target
	}
	return path + "?" + values.Encode()
}
