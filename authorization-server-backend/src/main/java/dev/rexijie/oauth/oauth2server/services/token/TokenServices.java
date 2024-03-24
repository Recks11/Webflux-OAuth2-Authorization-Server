package dev.rexijie.oauth.oauth2server.services.token;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
public interface TokenServices extends TokenAuthenticationConverter {
    Mono<OAuth2Token> createAccessToken(Authentication authentication);
    Mono<OAuth2Token> refreshAccessToken(RefreshToken token, RefreshTokenRequest request);
    Mono<OAuth2Token> getAccessToken(Authentication authentication);
}
