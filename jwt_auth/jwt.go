package jwt_auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JWTAuth struct {
	SecretKey string
}

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func NewJWTAuth(secret string) *JWTAuth {
	return &JWTAuth{SecretKey: secret}
}

func (j *JWTAuth) GenerateToken(userID, username string, expiry time.Duration, refreshExpiry time.Duration) (string, string, error) {
	ac := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	at, err := jwt.NewWithClaims(jwt.SigningMethodHS256, ac).SignedString([]byte(j.SecretKey))

	if err != nil {
		return "", "", err
	}

	rc := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	rt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, rc).SignedString([]byte(j.SecretKey))
	if err != nil {
		return "", "", err
	}

	return at, rt, nil
}

func (j *JWTAuth) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func (j *JWTAuth) RefreshToken(tokenString string, expiry time.Duration, refreshExpiry time.Duration) (string, string, error) {
	claims, err := j.ValidateToken(tokenString)

	if err != nil {
		return "", "", errors.New("invalid token")
	}

	at, rt, err := j.GenerateToken(claims.UserID, claims.Username, expiry, refreshExpiry)

	if err != nil {
		return "", "", errors.New("error creating when generate token")
	}

	return at, rt, nil
}
