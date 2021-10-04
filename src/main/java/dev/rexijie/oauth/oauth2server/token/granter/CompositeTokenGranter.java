package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.Map;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.OAuthErrors.UNSUPPORTED_GRANT_TYPE;

@Component
public class CompositeTokenGranter implements TokenGranter {

    private final Map<String, TokenGranter> tokenGranterMap;

    public CompositeTokenGranter(TokenServices tokenServices,
                                 @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager userAuthenticationManager,
                                 @Qualifier("clientAuthenticationManager") ReactiveAuthenticationManager clientAuthenticationManager,
                                 ReactiveAuthorizationCodeServices authorizationCodeServices) {

        this.tokenGranterMap = Map.of(
                AuthorizationGrantType.PASSWORD.getValue(), new ResourceOwnerPasswordCredentialsTokenGranter(tokenServices, userAuthenticationManager),
                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices)
        );
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (request.getScopes().isEmpty()) return Mono.error(INVALID_SCOPE_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        Mono<OAuth2Token> tokenGranterMono = Mono.just(tokenGranterMap)
                .map(map -> map.get(authorizationRequest.getGrantType()))
                .doOnError(err -> {throw Exceptions.propagate(new OAuthError(UNSUPPORTED_GRANT_TYPE));})
                .flatMap(tokenGranter -> tokenGranter.grantToken(authentication, authorizationRequest));

        return validateRequest(authorizationRequest)
                .then(tokenGranterMono);
    }
}
