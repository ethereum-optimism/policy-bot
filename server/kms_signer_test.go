// Copyright 2026 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v4"
	"github.com/googleapis/gax-go/v2"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

type fakeKMS struct {
	key      *rsa.PrivateKey
	err      error
	mutate   func(*kmspb.AsymmetricSignResponse)
	requests []*kmspb.AsymmetricSignRequest
}

func (f *fakeKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("request has no deadline")
	}

	digest := req.GetDigest().GetSha256()
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest)
	if err != nil {
		return nil, err
	}

	res := &kmspb.AsymmetricSignResponse{
		Name:                 req.GetName(),
		Signature:            sig,
		SignatureCrc32C:      wrapperspb.Int64(crc32c(sig)),
		VerifiedDigestCrc32C: req.GetDigestCrc32C().GetValue() == crc32c(digest),
	}
	if f.mutate != nil {
		f.mutate(res)
	}
	return res, nil
}

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func testClaims() *jwt.RegisteredClaims {
	now := time.Now().Truncate(time.Second)
	return &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(90 * time.Second)),
		Issuer:    "1234",
	}
}

func TestKMSSignerSign(t *testing.T) {
	key := newTestKey(t)
	fake := &fakeKMS{key: key}
	signer := newKMSSigner(fake, testKeyName)

	token, err := signer.Sign(testClaims())
	require.NoError(t, err)

	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(tok *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Equal(t, "RS256", parsed.Header["alg"])
	assert.Equal(t, "1234", parsed.Claims.(*jwt.RegisteredClaims).Issuer)

	expected, err := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims()).SignedString(key)
	require.NoError(t, err)
	assert.Equal(t, expected, token, "PKCS1 v1.5 signatures are deterministic, so the token must match a local RS256 signature")

	require.Len(t, fake.requests, 1)
	assert.Equal(t, testKeyName, fake.requests[0].GetName())
	assert.Len(t, fake.requests[0].GetDigest().GetSha256(), 32)
	assert.NotNil(t, fake.requests[0].GetDigestCrc32C())
}

func TestKMSSignerWithClientCreator(t *testing.T) {
	key := newTestKey(t)

	var authorization string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 1234, "slug": "policy-bot"}`))
	}))
	defer srv.Close()

	cc := githubapp.NewClientCreator(srv.URL, srv.URL+"/graphql", 1234, nil,
		githubapp.WithSigner(newKMSSigner(&fakeKMS{key: key}, testKeyName)),
	)
	client, err := cc.NewAppClient()
	require.NoError(t, err)

	app, _, err := client.Apps.Get(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, "policy-bot", app.GetSlug())

	token, ok := strings.CutPrefix(authorization, "Bearer ")
	require.True(t, ok, "authorization header must carry a bearer token")

	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(tok *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	assert.Equal(t, "1234", parsed.Claims.(*jwt.RegisteredClaims).Issuer)
}

func TestKMSSignerErrors(t *testing.T) {
	tests := map[string]*fakeKMS{
		"kmsError": {
			err: errors.New("permission denied"),
		},
		"wrongKeyName": {
			mutate: func(res *kmspb.AsymmetricSignResponse) {
				res.Name = "projects/p/locations/global/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1"
			},
		},
		"digestNotVerified": {
			mutate: func(res *kmspb.AsymmetricSignResponse) {
				res.VerifiedDigestCrc32C = false
			},
		},
		"missingSignatureChecksum": {
			mutate: func(res *kmspb.AsymmetricSignResponse) {
				res.SignatureCrc32C = nil
			},
		},
		"corruptSignature": {
			mutate: func(res *kmspb.AsymmetricSignResponse) {
				res.Signature[0] ^= 0xff
			},
		},
	}

	key := newTestKey(t)
	for name, fake := range tests {
		t.Run(name, func(t *testing.T) {
			fake.key = key
			signer := newKMSSigner(fake, testKeyName)

			token, err := signer.Sign(testClaims())
			assert.Error(t, err)
			assert.Empty(t, token)
		})
	}
}

func TestValidateAppKey(t *testing.T) {
	tests := map[string]struct {
		PrivateKey string
		KMSKey     string
		Valid      bool
	}{
		"privateKeyOnly":                {PrivateKey: "pem", Valid: true},
		"kmsKeyOnly":                    {KMSKey: testKeyName, Valid: true},
		"both":                          {PrivateKey: "pem", KMSKey: testKeyName},
		"neither":                       {},
		"whitespaceKMSKeyOnly":          {KMSKey: "  \n"},
		"whitespacePrivateKeyAndKMSKey": {PrivateKey: " \t", KMSKey: testKeyName, Valid: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var c Config
			c.Github.App.PrivateKey = test.PrivateKey
			c.Signing.GCPKMSKey = test.KMSKey

			err := c.ValidateAppKey()
			if test.Valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestParseConfigSigning(t *testing.T) {
	c, err := ParseConfig([]byte("signing:\n  gcp_kms_key: " + testKeyName + "\n"))
	require.NoError(t, err)
	assert.Equal(t, testKeyName, c.Signing.GCPKMSKey)

	t.Setenv("POLICYBOT_SIGNING_GCP_KMS_KEY", " from-env\n")
	c, err = ParseConfig([]byte("{}"))
	require.NoError(t, err)
	assert.Equal(t, "from-env", c.Signing.GCPKMSKey)
}

func TestParseConfigSigningEmptyEnvIgnored(t *testing.T) {
	for _, v := range []string{"", "   "} {
		t.Setenv("POLICYBOT_SIGNING_GCP_KMS_KEY", v)
		c, err := ParseConfig([]byte("signing:\n  gcp_kms_key: " + testKeyName + "\n"))
		require.NoError(t, err)
		assert.Equal(t, testKeyName, c.Signing.GCPKMSKey)
	}
}
