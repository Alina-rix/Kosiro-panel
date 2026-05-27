package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"kosiro/agent/internal/adminkey"
)

type ctxKey int

const ctxClaims ctxKey = 1

func BearerAuth(jwtSecret, adminToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			raw = strings.TrimSpace(raw)
			if raw == "" {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			if adminToken != "" && adminkey.Equal(raw, adminToken) {
				next.ServeHTTP(w, r)
				return
			}
			if adminToken != "" && !adminkey.Valid(adminToken) && len(raw) == len(adminToken) &&
				subtle.ConstantTimeCompare([]byte(raw), []byte(adminToken)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
			tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
				if t.Method != jwt.SigningMethodHS256 {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(jwtSecret), nil
			})
			if err != nil || !tok.Valid {
				writeErr(w, http.StatusUnauthorized, "invalid token")
				return
			}
			if claims, ok := tok.Claims.(jwt.MapClaims); ok {
				r = r.WithContext(context.WithValue(r.Context(), ctxClaims, claims))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
