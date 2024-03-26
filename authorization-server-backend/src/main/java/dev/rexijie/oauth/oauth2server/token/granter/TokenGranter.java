package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.token.AuthorizationTokenResponse;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

public interface TokenGranter {

    Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest authorizationRequest);

    Mono<AuthorizationTokenResponse> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest);
}
