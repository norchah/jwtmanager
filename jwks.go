package jwtmanager

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWKSKey represents a key in JWKS format.
type JWKSKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// toJWKSKey converts an RSA public key to JWKS format.
func toJWKSKey(kid string, pubKey *rsa.PublicKey) JWKSKey {
	return JWKSKey{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

// GetJWKS returns JWKS JSON for public key distribution.
func (m *JWTManager) GetJWKS() ([]byte, error) {
	keys := make([]JWKSKey, 0, len(m.config.PublicKeys))
	for kid, pubKey := range m.config.PublicKeys {
		keys = append(keys, toJWKSKey(kid, pubKey))
	}
	jwks := map[string]interface{}{
		"keys": keys,
	}
	return json.Marshal(jwks)
}
