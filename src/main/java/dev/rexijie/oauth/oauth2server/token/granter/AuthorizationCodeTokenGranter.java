package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.CLIENT_AUTHENTICATION_METHOD;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.OAuthErrors.INVALID_REQUEST;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.OAuthErrors.UNAUTHORIZED_CLIENT;

public class AuthorizationCodeTokenGranter extends AbstractOAuth2TokenGranter {

    private final ReactiveAuthorizationCodeServices authorizationCodeServices;

    public AuthorizationCodeTokenGranter(TokenServices tokenServices,
                                         ReactiveAuthorizationCodeServices authorizationCodeServices) {
        super(tokenServices, null);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    public Mono<AuthorizationRequest> validateRequest(AuthorizationRequest request) {
        if (request.getAttribute("code") == null)
            throw Exceptions.propagate(new OAuthError(INVALID_REQUEST, "missing authorization code"));
        if (request.getRedirectUri() == null)
            throw Exceptions.propagate(new OAuthError(INVALID_REQUEST, "missing redirect_uri"));
//        if (request.getAttribute(CLIENT_AUTHENTICATION_METHOD) == null)
//            return Mono.error(new OAuthError(UNAUTHORIZED_CLIENT, "missing client authentication"));
        return Mono.just(request);
    }

    @Override
    // TODO (Authenticate client before generating token)
    // TODO a code has to be bound to a client and user authentication.
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authorizationRequest)
                .flatMap(request -> {
                    String code = request.getAttribute("code");
                    return authorizationCodeServices.consumeAuthorizationCode(code, authentication)
                            .flatMap(auth -> getTokenServices().createAccessToken(auth));
                });
    }

    @Override
    protected OAuth2Authentication createAuthenticationToken(Authentication authentication, OAuth2AuthorizationRequest authorizationRequest) {
        return OAuth2Authentication.from(authentication);
    }
}
