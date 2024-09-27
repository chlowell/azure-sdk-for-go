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
// It handles [Continuous Access Evaluation] (CAE) challenges.
//
// [Continuous Access Evaluation]: https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation
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
		if res.Header.Get(shared.HeaderWWWAuthenticate) != "" {
			caeChallenge, bearerChallenges, parseErr := parseCAEChallenge(res)
			if parseErr != nil {
				return res, parseErr
			}
			switch {
			case b.authzHandler.OnChallenge != nil && (caeChallenge == nil || bearerChallenges > 1):
				// client provided a challenge handler, and the response has no CAE challenge or
				// has multiple Bearer challenges. This policy can't handle the first case or
				// interpret the second, so it defers to the client's handler.
				if err = b.authzHandler.OnChallenge(req, res, b.authenticateAndAuthorize(req)); err == nil {
					if res, err = req.Next(); err == nil && res.StatusCode == http.StatusUnauthorized {
						// Client handled the previous challenge but the server responded with another. If this
						// response includes a CAE challenge, handle that here, ignoring any other challenges.
						b.mainResource.Expire()
						if caeChallenge, _, err = parseCAEChallenge(res); caeChallenge != nil {
							tro := policy.TokenRequestOptions{
								Claims: caeChallenge.params["claims"],
								Scopes: b.scopes,
							}
							if err = b.authenticateAndAuthorize(req)(tro); err == nil {
								res, err = req.Next()
							}
						}
					}
				}
			case caeChallenge != nil:
				// response has a Bearer CAE challenge this policy can handle
				tro := policy.TokenRequestOptions{
					Claims: caeChallenge.params["claims"],
					Scopes: b.scopes,
				}
				if err = b.authenticateAndAuthorize(req)(tro); err == nil {
					res, err = req.Next()
				}
			default:
				// non-CAE challenge and no handler: return the 401 to the pipeline
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

// parseCAEChallenge returns:
//   - a *authChallenge representing Response's CAE challenge (nil when Response has none)
//   - a count of Response's Bearer challenges, including any CAE challenge
//   - a NonRetriableError, if Response includes a CAE challenge having invalid claims
func parseCAEChallenge(res *http.Response) (*authChallenge, int, error) {
	var (
		caeChallenge *authChallenge
		count        int
		err          error
	)
	challenges, allParsed := parseChallenges(res)
	for _, c := range challenges {
		if c.scheme == "Bearer" {
			count++
			if claims := c.params["claims"]; claims != "" && c.params["error"] == "insufficient_claims" {
				b, de := base64.StdEncoding.DecodeString(claims)
				if de != nil {
					// don't include the decoding error because it's something
					// unhelpful like "illegal base64 data at input byte 42"
					err = errorinfo.NonRetriableError(errors.New("authentication challenge contains invalid claims: " + claims))
					break
				}
				c.params["claims"] = string(b)
				caeChallenge = &c
			}
		}
	}
	if !allParsed {
		// recount Bearer challenges, including unparsed ones this time, because whether the response
		// carries multiple Bearer challenges affects the policy's decision to handle a CAE challenge
		count = 0
		for _, h := range res.Header.Values(shared.HeaderWWWAuthenticate) {
			// the space isn't a typo. RFC 7235 specifies a space follows the scheme,
			// and we don't want to count e.g. "Foo bar=Bearer" as a Bearer challenge
			count += strings.Count(h, "Bearer ")
		}
	}
	return caeChallenge, count, err
}

var (
	challenge, challengeParams *regexp.Regexp
	once                       = &sync.Once{}
)

type authChallenge struct {
	scheme string
	params map[string]string
}

// parseChallenges returns a slice of authentication challenges from the Response and a bool indicating
// whether this slice includes all the Response's challenges. When this bool is false, it means the
// header contains challenges this function can't parse.
func parseChallenges(res *http.Response) ([]authChallenge, bool) {
	once.Do(func() {
		// matches challenges having quoted parameters, capturing scheme and parameters
		challenge = regexp.MustCompile(`(?:(\w+) ((?:\w+="[^"]*",?\s*)+))`)
		// captures parameter names and values in a match of the above expression
		challengeParams = regexp.MustCompile(`(\w+)="([^"]*)"`)
	})
	var (
		extra  int
		parsed []authChallenge
	)
	// WWW-Authenticate can have multiple values, each containing multiple challenges
	for _, h := range res.Header.Values(shared.HeaderWWWAuthenticate) {
		extra += len(h)
		for _, sm := range challenge.FindAllStringSubmatch(h, -1) {
			// sm is [challenge, scheme, params]
			extra -= len(sm[0])
			// len checks aren't necessary but save you from wondering whether this function could panic
			if len(sm) == 3 {
				c := authChallenge{
					params: make(map[string]string),
					scheme: sm[1],
				}
				for _, sm := range challengeParams.FindAllStringSubmatch(sm[2], -1) {
					// sm is [key="value", key, value]
					if len(sm) == 3 {
						c.params[sm[1]] = sm[2]
					}
				}
				parsed = append(parsed, c)
			}
		}
	}
	// if extra > 0, WWW-Authenticate contains text that doesn't match
	// the challenge regex i.e., a challenge this function can't parse
	return parsed, extra == 0
}
