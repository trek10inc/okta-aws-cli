// Package oktaauth exposes Okta device authorization to consumers outside of
// this module.
package oktaauth

import (
	"slices"
	"strings"

	"github.com/okta/okta-aws-cli/v2/internal/config"
	"github.com/okta/okta-aws-cli/v2/internal/logger"
	"github.com/okta/okta-aws-cli/v2/internal/utils"
	"github.com/okta/okta-aws-cli/v2/internal/webssoauth"
)

// AccessToken Returns an Okta access token granted all of requiredScopes. The
// token cached by the web SSO flow is reused when it is unexpired and its
// granted scopes cover requiredScopes, otherwise device authorization is run
// and the new token is cached.
func AccessToken(orgDomain, oidcClientID string, requiredScopes []string, openBrowser bool) (string, error) {
	cfg, err := config.NewConfig(&config.Attributes{
		OrgDomain:        orgDomain,
		OIDCAppID:        oidcClientID,
		CacheAccessToken: true,
		OpenBrowser:      openBrowser,
	})
	if err != nil {
		return "", err
	}
	cfg.Logger = &logger.FullLogger{}

	if at := utils.CachedAccessToken(cfg); at != nil && grantsScopes(at.Scope, requiredScopes) {
		return at.AccessToken, nil
	}

	w, err := webssoauth.NewWebSSOAuthentication(cfg)
	if err != nil {
		return "", err
	}
	at, err := w.FetchAccessToken()
	if err != nil {
		return "", err
	}
	utils.CacheAccessToken(cfg, at)

	return at.AccessToken, nil
}

func grantsScopes(granted string, required []string) bool {
	scopes := strings.Fields(granted)
	for _, scope := range required {
		if !slices.Contains(scopes, scope) {
			return false
		}
	}

	return true
}
