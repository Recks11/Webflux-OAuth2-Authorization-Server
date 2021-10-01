package dev.rexijie.oauth.oauth2server.api.domain;

import org.springframework.security.core.Authentication;

/**
 * An Authorization request containing the initial Authorization request and the user authentication.
 */
public record OAuth2AuthorizationRequest(
        AuthorizationRequest storedRequest,
        Authentication authentication,
        OAuth2TokenRequest tokenRequest
) {
    public OAuth2AuthorizationRequest(AuthorizationRequest authorizationRequest, Authentication authentication) {
        this(authorizationRequest, authentication, null);
    }

    public static OAuth2AuthorizationRequest withTokenRequest(
            OAuth2AuthorizationRequest initialRequest,
            OAuth2TokenRequest tokenRequest) {
        return new OAuth2AuthorizationRequest(
                initialRequest.storedRequest(),
                initialRequest.authentication(),
                tokenRequest);
    }
}
