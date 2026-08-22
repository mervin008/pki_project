package api

import "github.com/gin-gonic/gin"

// unexpectedQuery returns the first query parameter this endpoint does not
// understand, or "".
//
// Used by list endpoints whose results get acted on. A filter that is silently
// dropped turns "the three certificates matching this name" into "every
// certificate", which is a difference nothing downstream can detect and which
// a delete loop cannot survive.
func unexpectedQuery(c *gin.Context, allowed ...string) string {
	known := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		known[name] = true
	}
	for name := range c.Request.URL.Query() {
		if !known[name] {
			return name
		}
	}
	return ""
}
