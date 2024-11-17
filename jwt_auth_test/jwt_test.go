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
	token, err := auth.GenerateToken(userId, username, 60*time.Second)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTAuthValidateToken(t *testing.T) {
	secret := "weareteam1"
	auth := jwt_auth.NewJWTAuth(secret)
	userId := "123"
	username := "john@doe.com"
	token, err := auth.GenerateToken(userId, username, 60*time.Second)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	claims, err := auth.ValidateToken(token)
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
