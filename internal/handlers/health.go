package handlers

import (
	"context"
	"database/sql"
	"github.com/labstack/echo/v4"
	"net/http"
	"time"
)

const healthPingTimeout = 2 * time.Second

// Health reports whether the server can reach its database. It is meant for
// container and load-balancer probes: 200 when a ping succeeds within a short
// timeout, 503 otherwise. The endpoint is unauthenticated and reveals nothing
// beyond up/down.
func Health(db *sql.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), healthPingTimeout)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}
}
