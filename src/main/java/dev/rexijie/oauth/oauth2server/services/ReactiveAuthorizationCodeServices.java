package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.auth.AuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

public interface ReactiveAuthorizationCodeServices {
    Mono<AuthorizationCodeWrapper> createAuthorizationCode(Authentication authentication);
    Mono<OAuth2Authentication> consumeAuthorizationCode(String code, Authentication clientAuthentication);
}
