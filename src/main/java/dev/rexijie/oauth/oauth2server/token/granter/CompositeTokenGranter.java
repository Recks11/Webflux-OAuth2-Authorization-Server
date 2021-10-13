package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
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

import static dev.rexijie.oauth.oauth2server.error.OAuthError.*;

@Component
public class CompositeTokenGranter implements TokenGranter {

    private final Map<AuthorizationGrantType, TokenGranter> tokenGranterMap;

    public CompositeTokenGranter(TokenServices tokenServices,
                                 @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager userAuthenticationManager,
                                 @Qualifier("clientAuthenticationManager") ReactiveAuthenticationManager clientAuthenticationManager,
                                 ReactiveAuthorizationCodeServices authorizationCodeServices) {

        this.tokenGranterMap = Map.of(
                AuthorizationGrantType.PASSWORD, new ResourceOwnerPasswordCredentialsTokenGranter(tokenServices, userAuthenticationManager),
                AuthorizationGrantType.AUTHORIZATION_CODE, new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices),
                AuthorizationGrantType.CLIENT_CREDENTIALS, new ClientCredentialsTokenGranter(tokenServices, clientAuthenticationManager)
        );
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (request.getScopes().isEmpty()) return Mono.error(INVALID_SCOPE_ERROR);
        if (request.getGrantType() == null) return Mono.error(INVALID_REQUEST_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        Mono<OAuth2Token> tokenGranterMono = Mono.just(tokenGranterMap)
                .map(granters -> getTokenGranterForRequest(granters, authorizationRequest))
                .flatMap(tokenGranter -> tokenGranter.grantToken(authentication, authorizationRequest));

        return validateRequest(authorizationRequest)
                .then(tokenGranterMono);
    }

    private TokenGranter getTokenGranterForRequest(Map<AuthorizationGrantType, TokenGranter> tokenGranterMap, AuthorizationRequest authorizationRequest) {
        var grantType = new AuthorizationGrantType(authorizationRequest.getGrantType());
        if (!tokenGranterMap.containsKey(grantType)) throw Exceptions.propagate(UNSUPPORTED_GRANT_TYPE_ERROR);
        return tokenGranterMap.get(grantType);
    }
}
