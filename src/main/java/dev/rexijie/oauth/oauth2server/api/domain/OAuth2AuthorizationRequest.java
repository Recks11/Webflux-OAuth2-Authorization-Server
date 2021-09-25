package dev.rexijie.oauth.oauth2server.api.domain;

import org.springframework.security.core.Authentication;

public record OAuth2AuthorizationRequest(
        AuthorizationRequest storedRequest,
        Authentication authentication
) { }
