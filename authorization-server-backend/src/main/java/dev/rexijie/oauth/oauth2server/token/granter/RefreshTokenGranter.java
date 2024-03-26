package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.AuthorizationTokenResponse;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

// TODO (Implement)
public class RefreshTokenGranter implements TokenGranter {

    public RefreshTokenGranter(TokenServices tokenServices) {

    }

    @Override
    public Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return Mono.empty();
    }

    @Override
    public Mono<AuthorizationTokenResponse> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return Mono.empty();
    }
}
