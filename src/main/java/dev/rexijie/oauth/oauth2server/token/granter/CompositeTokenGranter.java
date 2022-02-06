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

import java.util.Collections;
import java.util.Map;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.*;

@Component
public class CompositeTokenGranter implements TokenGranter {

    private final Map<AuthorizationGrantType, TokenGranter> tokenGranterMap;

    public CompositeTokenGranter(TokenServices tokenServices,
                                 @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager userAuthenticationManager,
                                 @Qualifier("clientAuthenticationManager") ReactiveAuthenticationManager clientAuthenticationManager,
                                 ReactiveAuthorizationCodeServices authorizationCodeServices) {

        this.tokenGranterMap = Collections.synchronizedMap(Map.of(
                AuthorizationGrantType.PASSWORD, new ResourceOwnerPasswordCredentialsTokenGranter(tokenServices, userAuthenticationManager),
                AuthorizationGrantType.AUTHORIZATION_CODE, new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices),
                AuthorizationGrantType.CLIENT_CREDENTIALS, new ClientCredentialsTokenGranter(tokenServices, clientAuthenticationManager)
        ));
    }

    @Override
    public Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest request) {
        if (request.getScope().isEmpty()) return Mono.error(INVALID_SCOPE_ERROR);
        if (request.getGrantType() == null) return Mono.error(INVALID_REQUEST_ERROR);
        return Mono.just(request);
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authentication, authorizationRequest)
                .flatMap(validReq -> {
                    var granter = getTokenGranterForRequest(tokenGranterMap, validReq);
                    return granter.grantToken(authentication, validReq);
                });
    }

    private TokenGranter getTokenGranterForRequest(Map<AuthorizationGrantType, TokenGranter> tokenGranterMap, AuthorizationRequest authorizationRequest) {
        var grantType = new AuthorizationGrantType(authorizationRequest.getGrantType());
        if (!tokenGranterMap.containsKey(grantType)) throw Exceptions.propagate(UNSUPPORTED_GRANT_TYPE_ERROR);
        return tokenGranterMap.get(grantType);
    }
}
