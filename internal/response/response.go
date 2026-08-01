// Package response provides a consistent JSON envelope for all API replies.
package response

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Envelope is the uniform shape returned by every endpoint.
type Envelope struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// APIError describes a failed request in a machine-readable way.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// OK writes a successful response with the given payload.
func OK(c *gin.Context, status int, data interface{}) {
	c.JSON(status, Envelope{
		Success:   true,
		Data:      data,
		Timestamp: now(),
	})
}

// Fail writes an error response with a stable error code.
func Fail(c *gin.Context, status int, code, message string) {
	c.JSON(status, Envelope{
		Success:   false,
		Error:     &APIError{Code: code, Message: message},
		Timestamp: now(),
	})
}

// Abort writes an error response and stops further handler execution.
func Abort(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, Envelope{
		Success:   false,
		Error:     &APIError{Code: code, Message: message},
		Timestamp: now(),
	})
}
