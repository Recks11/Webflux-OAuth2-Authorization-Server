package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
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

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;

@Component
public class CompositeTokenGranter implements TokenGranter {

    private final TokenServices tokenServices;
    private final ReactiveAuthenticationManager userAuthenticationManager;
    private final ReactiveAuthenticationManager clientAuthenticationManager;
    private final Map<String, TokenGranter> tokenGranterMap;

    public CompositeTokenGranter(TokenServices tokenServices,
                                 @Qualifier("userAuthenticationManager") ReactiveAuthenticationManager userAuthenticationManager,
                                 @Qualifier("clientAuthenticationManager") ReactiveAuthenticationManager clientAuthenticationManager) {
        this.tokenServices = tokenServices;
        this.userAuthenticationManager = userAuthenticationManager;
        this.clientAuthenticationManager = clientAuthenticationManager;
        this.tokenGranterMap = Map.of(
                AuthorizationGrantType.PASSWORD.getValue(), new ResourceOwnerPasswordCredentialsTokenGranter(tokenServices, userAuthenticationManager)
        );
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (request.getScopes().isEmpty()) return Mono.error(INVALID_SCOPE_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authorizationRequest).then(
                tokenGranterMap.get(authorizationRequest.getGrantType())
                        .grantToken(authentication, authorizationRequest)
        );
    }
}
