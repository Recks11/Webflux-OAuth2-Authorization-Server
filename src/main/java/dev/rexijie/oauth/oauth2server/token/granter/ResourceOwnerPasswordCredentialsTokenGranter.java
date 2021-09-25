package dev.rexijie.oauth.oauth2server.token.granter;


import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.TokenServices;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

public class ResourceOwnerPasswordCredentialsTokenGranter implements TokenGranter {

    private final TokenServices tokenServices;
    private final ReactiveAuthenticationManager authenticationManager;

    public ResourceOwnerPasswordCredentialsTokenGranter(TokenServices tokenServices,
                                                        ReactiveAuthenticationManager authenticationManager) {
        this.tokenServices = tokenServices;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public boolean canGrantToken(AuthorizationRequest request) {
        return AuthorizationGrantType.PASSWORD.equals(new AuthorizationGrantType(request.getGrantType()));
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        var usernameAndPasswordToken = new UsernamePasswordAuthenticationToken(
                authorizationRequest.getAttribute("username"),
                authorizationRequest.getAttribute("password")
        );

        var oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest(
                authorizationRequest,
                usernameAndPasswordToken
        );

        return authenticationManager.authenticate(usernameAndPasswordToken)
                .doOnError(throwable -> {throw Exceptions.propagate(throwable);})
                .flatMap(auth -> tokenServices.createAccessToken(authentication, oAuth2AuthorizationRequest));
    }
}
