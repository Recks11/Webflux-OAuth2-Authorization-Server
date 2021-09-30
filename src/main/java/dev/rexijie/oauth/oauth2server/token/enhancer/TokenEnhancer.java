package dev.rexijie.oauth.oauth2server.token.enhancer;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

public interface TokenEnhancer {
    Mono<OAuth2Token> enhance(OAuth2AccessToken token, Authentication authentication);
}
