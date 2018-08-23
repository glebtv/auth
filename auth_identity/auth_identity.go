package auth_identity

import (
	"time"

	"github.com/glebtv/auth/claims"
	null "gopkg.in/guregu/null.v3"
)

// AuthIdentity auth identity session model
type AuthIdentity struct {
	ID int64 `gorm:"primary_key" json:"id"`
	Basic
	SignLogs
}

func (AuthIdentity) TableName() string {
	return "identities"
}

// Basic basic information about auth identity
type Basic struct {
	Provider          string // phone, email, wechat, github...
	UID               string `gorm:"column:uid"`
	EncryptedPassword string
	UserID            null.Int
	ConfirmedAt       *time.Time
}

func (Basic) TableName() string {
	return "identities"
}

// ToClaims convert to auth Claims
func (basic Basic) ToClaims() *claims.Claims {
	claims := claims.Claims{}
	claims.Provider = basic.Provider
	claims.Id = basic.UID
	claims.UserID = basic.UserID.Int64
	return &claims
}
