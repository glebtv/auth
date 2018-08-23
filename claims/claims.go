package claims

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	null "gopkg.in/guregu/null.v3"
)

// Claims auth claims
type Claims struct {
	Provider                         string         `json:"provider,omitempty"`
	UserID                           null.Int       `json:"userid,omitempty"`
	LastLoginAt                      *time.Time     `json:"last_login,omitempty"`
	LastActiveAt                     *time.Time     `json:"last_active,omitempty"`
	LongestDistractionSinceLastLogin *time.Duration `json:"distraction_time,omitempty"`
	jwt.StandardClaims
}

// ToClaims implement ClaimerInterface
func (claims *Claims) ToClaims() *Claims {
	return claims
}

// ClaimerInterface claimer interface
type ClaimerInterface interface {
	ToClaims() *Claims
}
