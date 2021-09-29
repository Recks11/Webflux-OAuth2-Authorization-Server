package dev.rexijie.oauth.oauth2server.token.granter;


import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;

public class ResourceOwnerPasswordCredentialsTokenGranter extends AbstractOAuth2TokenGranter {

    public ResourceOwnerPasswordCredentialsTokenGranter(TokenServices tokenServices,
                                                        ReactiveAuthenticationManager authenticationManager) {
        super(tokenServices, authenticationManager);
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (!AuthorizationGrantType.PASSWORD.equals(new AuthorizationGrantType(request.getGrantType())))
            return Mono.error(INVALID_SCOPE_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authorizationRequest)
                .then(authenticateUsernameAndPassword(authorizationRequest)
                        .doOnError(throwable -> {throw Exceptions.propagate(throwable);})
                        .map(oAuth2AuthorizationRequest -> createAuthenticationToken(authentication, oAuth2AuthorizationRequest))
                        .flatMap(getTokenServices()::createAccessToken));
    }
}
