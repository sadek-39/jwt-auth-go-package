package jwt_testing

import (
	"github.com/sadek-39/jwt-auth/jwt_auth"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestJWTAuthGenerateToken(t *testing.T) {
	secret := "weareteam1"
	auth := jwt_auth.NewJWTAuth(secret)

	userId := "123"
	username := "john@doe.com"
	at, rt, err := auth.GenerateToken(userId, username, 60*time.Second, 24*time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
}

func TestJWTAuthValidateToken(t *testing.T) {
	secret := "weareteam1"
	auth := jwt_auth.NewJWTAuth(secret)
	userId := "123"
	username := "john@doe.com"
	at, rt, err := auth.GenerateToken(userId, username, 60*time.Second, 24*time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
	claims, err := auth.ValidateToken(at)
	assert.Equal(t, userId, claims.UserID)
	assert.Equal(t, username, claims.Username)
}

func TestInvalidToken(t *testing.T) {
	secret := "mysecretkey"
	auth := jwt_auth.NewJWTAuth(secret)

	invalidToken := "invalid.jwt.token"
	_, err := auth.ValidateToken(invalidToken)
	assert.Error(t, err)
}

func TestRefreshToken(t *testing.T) {
	secret := "weareteam1"
	auth := jwt_auth.NewJWTAuth(secret)
	userId := "123"
	username := "john@doe.com"
	at, rt, err := auth.GenerateToken(userId, username, 60*time.Second, 24*time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
	at, rt, err = auth.RefreshToken(rt, 60*time.Second, 24*time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
}
