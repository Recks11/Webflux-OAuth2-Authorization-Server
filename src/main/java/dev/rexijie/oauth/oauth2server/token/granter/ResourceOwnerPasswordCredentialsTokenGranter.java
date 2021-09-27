package dev.rexijie.oauth.oauth2server.token.granter;


import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;

public class ResourceOwnerPasswordCredentialsTokenGranter implements TokenGranter {

    private final TokenServices tokenServices;
    private final ReactiveAuthenticationManager authenticationManager;

    public ResourceOwnerPasswordCredentialsTokenGranter(TokenServices tokenServices,
                                                        ReactiveAuthenticationManager authenticationManager) {
        this.tokenServices = tokenServices;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (!AuthorizationGrantType.PASSWORD.equals(new AuthorizationGrantType(request.getGrantType())))
            return Mono.error(INVALID_SCOPE_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        var usernameAndPasswordToken = new UsernamePasswordAuthenticationToken(
                authorizationRequest.getAttribute("username"),
                authorizationRequest.getAttribute("password")
        );

        return validateRequest(authorizationRequest)
                .then(authenticationManager.authenticate(usernameAndPasswordToken)
                        .map(returnedAuth -> new OAuth2AuthorizationRequest(authorizationRequest, returnedAuth))
                        .doOnError(throwable -> {
                            throw Exceptions.propagate(throwable);
                        })
                        .map(oAuth2AuthorizationRequest -> createAuthenticationToken(authentication, oAuth2AuthorizationRequest))
                        .flatMap(tokenServices::createAccessToken));
    }

    private OAuth2Authentication createAuthenticationToken(Authentication authentication,
                                                           OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
        OAuth2Authentication auth = new OAuth2Authentication(oAuth2Authentication.getPrincipal(),
                oAuth2Authentication.getCredentials(),
                oAuth2Authentication.getAuthorities(),
                authorizationRequest);
        auth.setAuthenticated(authentication.isAuthenticated());
        auth.setDetails(oAuth2Authentication.getDetails());
        return auth;
    }
}
