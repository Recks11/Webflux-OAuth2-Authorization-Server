package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

public interface ReactiveAuthorizationCodeServices {
    Mono<OAuth2ApprovalAuthorizationToken> createAuthorizationCode(Authentication authentication);
    Mono<OAuth2ApprovalAuthorizationToken> consumeAuthorizationCode(String code);
}
