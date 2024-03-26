package dev.rexijie.oauth.oauth2server.token;

import org.springframework.security.oauth2.core.OAuth2Token;

import java.util.Optional;
import java.util.Set;

public record AuthorizationTokenResponse(
        OAuth2Token accessToken,
        Set<String> scopes,
        Optional<OAuth2Token> refreshToken) {
}
