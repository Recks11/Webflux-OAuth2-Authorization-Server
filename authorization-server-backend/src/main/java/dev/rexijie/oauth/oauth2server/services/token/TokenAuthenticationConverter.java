package dev.rexijie.oauth.oauth2server.services.token;

import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

public interface TokenAuthenticationConverter {
    Mono<OAuth2Authentication> readAuthentication(OAuth2Token auth2Token, OAuth2Authentication authentication);
}
