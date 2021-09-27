package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

public interface TokenGranter {

    Mono<Void> validateRequest(AuthorizationRequest request);
    Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest);
}
