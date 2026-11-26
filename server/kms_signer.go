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
	"crypto/sha256"
	"encoding/base64"
	"hash/crc32"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v4"
	"github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const DefaultKMSSignTimeout = 10 * time.Second

type asymmetricSigner interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// KMSSigner signs GitHub App JWTs with RS256 using an asymmetric signing key
// version in Google Cloud KMS. The key version must use the
// RSA_SIGN_PKCS1_2048_SHA256 algorithm, which matches the 2048-bit RSA private
// keys that GitHub generates for apps.
type KMSSigner struct {
	client  asymmetricSigner
	keyName string
	timeout time.Duration
}

// NewKMSSigner creates a KMSSigner that uses application default credentials
// to call Cloud KMS. keyName is the full resource name of a key version, like
// projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V.
func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Cloud KMS client")
	}
	return newKMSSigner(client, keyName), nil
}

func newKMSSigner(client asymmetricSigner, keyName string) *KMSSigner {
	return &KMSSigner{
		client:  client,
		keyName: keyName,
		timeout: DefaultKMSSignTimeout,
	}
}

// Sign implements the ghinstallation.Signer interface.
func (s *KMSSigner) Sign(claims jwt.Claims) (string, error) {
	signingString, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SigningString()
	if err != nil {
		return "", errors.Wrap(err, "failed to encode JWT")
	}

	digest := sha256.Sum256([]byte(signingString))

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	res, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest[:]},
		},
		DigestCrc32C: wrapperspb.Int64(crc32c(digest[:])),
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to sign JWT with Cloud KMS")
	}

	if res.GetName() != s.keyName {
		return "", errors.Errorf("Cloud KMS signed with key %q, expected %q", res.GetName(), s.keyName)
	}
	if !res.GetVerifiedDigestCrc32C() {
		return "", errors.New("Cloud KMS did not verify the digest checksum")
	}
	if res.GetSignatureCrc32C() == nil || res.GetSignatureCrc32C().GetValue() != crc32c(res.GetSignature()) {
		return "", errors.New("Cloud KMS signature checksum does not match")
	}

	return signingString + "." + base64.RawURLEncoding.EncodeToString(res.GetSignature()), nil
}

func crc32c(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}
