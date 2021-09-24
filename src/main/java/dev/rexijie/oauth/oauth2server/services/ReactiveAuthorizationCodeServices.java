package dev.rexijie.oauth.oauth2server.services;

import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

public interface ReactiveAuthorizationCodeServices {

    Mono<String> createAuthorizationCode(Authentication authentication);
    Mono<String> consumeAuthorizationCode(String code);
}
