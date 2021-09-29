package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

public class AuthorizationCodeTokenGranter extends AbstractOAuth2TokenGranter {

    public AuthorizationCodeTokenGranter(TokenServices tokenServices,
                                         ReactiveAuthenticationManager authenticationManager) {
        super(tokenServices, authenticationManager);
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authorizationRequest)
                .then(processRequest(authentication, authorizationRequest));
    }

    private Mono<OAuth2Token> processRequest(Authentication clientAuthentication, AuthorizationRequest authorizationRequest) {

        return authenticateUsernameAndPassword(authorizationRequest)
                .map(oAuth2AuthorizationRequest -> createAuthenticationToken(clientAuthentication, oAuth2AuthorizationRequest))
                .flatMap(oAuth2AuthorizationRequest -> getTokenServices().getAccessToken(oAuth2AuthorizationRequest));
    }
}
