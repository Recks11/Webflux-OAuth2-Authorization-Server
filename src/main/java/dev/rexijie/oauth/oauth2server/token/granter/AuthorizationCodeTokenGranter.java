package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.OAuthErrors.INVALID_REQUEST;

public class AuthorizationCodeTokenGranter extends AbstractOAuth2TokenGranter {

    private final ReactiveAuthorizationCodeServices authorizationCodeServices;

    public AuthorizationCodeTokenGranter(TokenServices tokenServices,
                                         ReactiveAuthorizationCodeServices authorizationCodeServices) {
        super(tokenServices, null);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (request.getAttribute("code") == null)
            return Mono.error(new OAuthError(INVALID_REQUEST, "missing authorization code"));
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return Mono.just(authorizationRequest)
                .doOnNext(this::validateRequest)
                .flatMap(request -> {
                    String code = request.getAttribute("code");

                    return authorizationCodeServices.consumeAuthorizationCode(code)
                            .flatMap(approvalToken -> {
                                var userAuth = new OAuth2Authentication(approvalToken.getPrincipal(), null);
                                userAuth.setAuthenticationStage(AuthenticationStage.COMPLETE);
                                    var auth = createAuthenticationToken(approvalToken,
                                            new OAuth2AuthorizationRequest(
                                                    approvalToken.getAuthorizationRequest(), userAuth));
//
                                return getTokenServices().createAccessToken(auth);
                            });
                });
    }

    @Override
    protected OAuth2Authentication createAuthenticationToken(Authentication authentication, OAuth2AuthorizationRequest authorizationRequest) {
        var auth = (OAuth2ApprovalAuthorizationToken) authentication;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(auth.getAuthorizedClientId(),
                null,
                null,
                authorizationRequest);
        oAuth2Authentication.setAuthenticated(authentication.isAuthenticated());
        oAuth2Authentication.setDetails(authentication.getDetails());
        return oAuth2Authentication;
    }
}
