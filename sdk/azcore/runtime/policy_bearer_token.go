// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/errorinfo"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/temporal"
)

// BearerTokenPolicy authorizes requests with bearer tokens acquired from a TokenCredential.
type BearerTokenPolicy struct {
	// mainResource is the resource to be retreived using the tenant specified in the credential
	mainResource *temporal.Resource[exported.AccessToken, acquiringResourceState]
	// the following fields are read-only
	authzHandler policy.AuthorizationHandler
	cred         exported.TokenCredential
	scopes       []string
	allowHTTP    bool
}

type acquiringResourceState struct {
	req *policy.Request
	p   *BearerTokenPolicy
	tro policy.TokenRequestOptions
}

// acquire acquires or updates the resource; only one
// thread/goroutine at a time ever calls this function
func acquire(state acquiringResourceState) (newResource exported.AccessToken, newExpiration time.Time, err error) {
	tk, err := state.p.cred.GetToken(&shared.ContextWithDeniedValues{Context: state.req.Raw().Context()}, state.tro)
	if err != nil {
		return exported.AccessToken{}, time.Time{}, err
	}
	return tk, tk.ExpiresOn, nil
}

// NewBearerTokenPolicy creates a policy object that authorizes requests with bearer tokens.
// cred: an azcore.TokenCredential implementation such as a credential object from azidentity
// scopes: the list of permission scopes required for the token.
// opts: optional settings. Pass nil to accept default values; this is the same as passing a zero-value options.
func NewBearerTokenPolicy(cred exported.TokenCredential, scopes []string, opts *policy.BearerTokenOptions) *BearerTokenPolicy {
	if opts == nil {
		opts = &policy.BearerTokenOptions{}
	}
	b := &BearerTokenPolicy{
		authzHandler: opts.AuthorizationHandler,
		cred:         cred,
		scopes:       scopes,
		mainResource: temporal.NewResource(acquire),
		allowHTTP:    opts.InsecureAllowCredentialWithHTTP,
	}
	return b
}

// authenticateAndAuthorize returns a function which authorizes req with a token from the policy's credential
func (b *BearerTokenPolicy) authenticateAndAuthorize(req *policy.Request) func(policy.TokenRequestOptions) error {
	return func(tro policy.TokenRequestOptions) error {
		tro.EnableCAE = true
		as := acquiringResourceState{p: b, req: req, tro: tro}
		tk, err := b.mainResource.Get(as)
		if err != nil {
			return err
		}
		req.Raw().Header.Set(shared.HeaderAuthorization, shared.BearerTokenPrefix+tk.Token)
		return nil
	}
}

func get(challenges []authChallenge) (*authChallenge, int, error) {
	var (
		bearerChallenges int
		caeChallenge     *authChallenge
		err              error
	)
	for _, c := range challenges {
		if c.scheme == "Bearer" {
			bearerChallenges++
			if claims := c.params["claims"]; claims != "" && c.params["error"] == "insufficient_claims" {
				pad := strings.Index(claims, "=")
				if pad >= 0 {
					claims = claims[:pad]
				}
				b, de := base64.RawURLEncoding.DecodeString(claims)
				if de != nil {
					// we don't include the decoding error because it's something
					// unhelpful like "illegal base64 data at input byte 42"
					err = errorinfo.NonRetriableError(errors.New("challenge contains invalid claims: " + claims))
					break
				}
				c.params["claims"] = string(b)
				caeChallenge = &c
			}
		}
	}
	return caeChallenge, bearerChallenges, err
}

// Do authorizes a request with a bearer token
func (b *BearerTokenPolicy) Do(req *policy.Request) (*http.Response, error) {
	// skip adding the authorization header if no TokenCredential was provided.
	// this prevents a panic that might be hard to diagnose and allows testing
	// against http endpoints that don't require authentication.
	if b.cred == nil {
		return req.Next()
	}

	if err := checkHTTPSForAuth(req, b.allowHTTP); err != nil {
		return nil, err
	}

	var err error
	if b.authzHandler.OnRequest != nil {
		err = b.authzHandler.OnRequest(req, b.authenticateAndAuthorize(req))
	} else {
		err = b.authenticateAndAuthorize(req)(policy.TokenRequestOptions{Scopes: b.scopes})
	}
	if err != nil {
		return nil, errorinfo.NonRetriableError(err)
	}

	res, err := req.Next()
	if err != nil {
		return nil, err
	}

	if res.StatusCode == http.StatusUnauthorized {
		b.mainResource.Expire()
		if h := res.Header.Get(shared.HeaderWWWAuthenticate); h != "" {
			challenges, x := parseChallenges(res)
			// TODO: do we care whether res has unparseable challenges?
			_ = x
			caeChallenge, bearerChallenges, parseErr := get(challenges)
			if parseErr != nil {
				return res, parseErr
			}
			switch {
			// call the client's challenge handler if any of the following is true:
			//   - res has no CAE challenge
			//   - res has more than one Bearer challenge
			case b.authzHandler.OnChallenge != nil && (caeChallenge == nil || bearerChallenges > 1):
				if err = b.authzHandler.OnChallenge(req, res, b.authenticateAndAuthorize(req)); err == nil {
					if res, err = req.Next(); err == nil && res.StatusCode == http.StatusUnauthorized {
						b.mainResource.Expire()
						challenges, _ := parseChallenges(res)
						caeChallenge, _, parseErr := get(challenges)
						if parseErr != nil {
							return res, parseErr
						}
						if caeChallenge != nil {
							tro := policy.TokenRequestOptions{
								Claims: caeChallenge.params["claims"],
								Scopes: b.scopes,
							}
							err = b.authenticateAndAuthorize(req)(tro)
							if err == nil {
								res, err = req.Next()
							}
						}
					}
				}
			// if res has a Bearer CAE challenge, this policy can handle it
			case caeChallenge != nil:
				tro := policy.TokenRequestOptions{
					Claims: caeChallenge.params["claims"],
					Scopes: b.scopes,
				}
				if err = b.authenticateAndAuthorize(req)(tro); err == nil {
					res, err = req.Next()
				}
			// no challenge handler from the client, no CAE challenge; return an error
			default:
				err = NewResponseError(res)
			}
		}
	}
	if err != nil {
		err = errorinfo.NonRetriableError(err)
	}
	return res, err
}

func checkHTTPSForAuth(req *policy.Request, allowHTTP bool) error {
	if strings.ToLower(req.Raw().URL.Scheme) != "https" && !allowHTTP {
		return errorinfo.NonRetriableError(errors.New("authenticated requests are not permitted for non TLS protected (https) endpoints"))
	}
	return nil
}

type authChallenge struct {
	scheme string
	params map[string]string
}

var (
	challenge, challengeParams *regexp.Regexp
	once                       = &sync.Once{}
)

// parseChallenges returns all res's authentication parseChallenges and a bool indicating
// whether the returned parseChallenges comprise the entire header
func parseChallenges(res *http.Response) ([]authChallenge, bool) {
	once.Do(func() {
		// this expression matches challenges having quoted parameters, capturing scheme and parameters
		challenge = regexp.MustCompile(`(?:(\w+) ((?:\w+="[^"]*",?\s*)+))`)
		// this expression captures parameter names and values in a match of the above expression
		challengeParams = regexp.MustCompile(`(\w+)="([^"]*)"`)
	})
	var (
		extra      int
		challenges []authChallenge
	)
	// WWW-Authenticate can have multiple values, each containing multiple challenges
	for _, h := range res.Header.Values(shared.HeaderWWWAuthenticate) {
		extra += len(h)
		for _, sm := range challenge.FindAllStringSubmatch(h, -1) {
			// sm is [full match, challenge scheme, challenge params]
			extra -= len(sm[0])
			// len checks aren't necessary but prevent you wondering whether this function could panic
			if len(sm) == 3 {
				c := authChallenge{
					params: make(map[string]string),
					scheme: sm[1],
				}
				for _, sm := range challengeParams.FindAllStringSubmatch(sm[2], -1) {
					// sm is [full match, parameter key, parameter value]
					if len(sm) == 3 {
						c.params[sm[1]] = sm[2]
					}
				}
				challenges = append(challenges, c)
			}
		}
	}
	return challenges, extra != 0
}
