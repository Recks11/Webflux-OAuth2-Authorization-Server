package dev.rexijie.oauth.oauth2server.token.enhancer;

import dev.rexijie.oauth.oauth2server.services.token.TokenAuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

public interface TokenEnhancer extends TokenAuthenticationConverter {
    Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication);
    Mono<Boolean> isEnhanced(OAuth2Token token);
}
