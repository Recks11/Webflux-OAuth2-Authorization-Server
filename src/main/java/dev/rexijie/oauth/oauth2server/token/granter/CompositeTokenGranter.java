package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;

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
    public boolean canGrantToken(AuthorizationRequest request) {
        return true;
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return tokenGranterMap.get(authorizationRequest.getGrantType())
                .grantToken(authentication, authorizationRequest);
    }
}
