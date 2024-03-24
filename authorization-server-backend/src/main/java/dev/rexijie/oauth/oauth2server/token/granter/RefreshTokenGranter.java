package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

// TODO (Implement)
public class RefreshTokenGranter implements TokenGranter {

    public RefreshTokenGranter(TokenServices tokenServices) {

    }

    @Override
    public Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return null;
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return null;
    }
}
