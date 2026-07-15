// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package userpass

import (
	"context"
	"crypto/rand"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/bcrypt"
)

const operationPrefixUserpass = "userpass"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend

	// Generate a random fake password hash at startup so no hardcoded hash
	// exists in the source. This hash is used as a timing decoy when a
	// login is attempted for a non-existent user.
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("userpass: failed to generate random bytes for fake password hash: " + err.Error())
	}
	fakeHash, err := bcrypt.GenerateFromPassword(randomBytes, bcrypt.DefaultCost)
	if err != nil {
		panic("userpass: failed to generate fake password hash: " + err.Error())
	}
	b.fakePasswordHash = fakeHash

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/*",
			},
		},

		Paths: []*framework.Path{
			pathUsers(&b),
			pathUsersList(&b),
			pathUserPolicies(&b),
			pathUserPassword(&b),
			pathLogin(&b),
		},

		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
	}

	return &b
}

type backend struct {
	*framework.Backend

	// fakePasswordHash is a bcrypt hash generated from a random secret at
	// startup. It is used as a timing decoy during login when the requested
	// user does not exist, preventing user-enumeration via response time.
	fakePasswordHash []byte
}

const backendHelp = `
The "userpass" credential provider allows authentication using
a combination of a username and password. No additional factors
are supported.

The username/password combination is configured using the "users/"
endpoints by a user with root access. Authentication is then done
by supplying the two fields for "login".
`
