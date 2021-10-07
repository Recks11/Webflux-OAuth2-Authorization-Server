package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_GRANT_ERROR;

public class ImplicitTokenGranter extends AbstractOAuth2TokenGranter {

    public ImplicitTokenGranter(TokenServices tokenServices, ReactiveAuthenticationManager authenticationManager) {
        super(tokenServices, authenticationManager);
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (!AuthorizationGrantType.IMPLICIT.equals(new AuthorizationGrantType(request.getGrantType())))
            throw Exceptions.propagate(INVALID_GRANT_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authorizationRequest)
                .then(Mono.empty());
    }
}
