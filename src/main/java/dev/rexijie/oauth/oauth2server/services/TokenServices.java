package dev.rexijie.oauth.oauth2server.services;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public interface TokenServices {
    Mono<OAuth2Token> createAccessToken(Authentication authentication);
    Mono<OAuth2Token> refreshAccessToken(RefreshToken token, RefreshTokenRequest request);
    Mono<OAuth2Token> getAccessToken(Authentication authentication);
}
