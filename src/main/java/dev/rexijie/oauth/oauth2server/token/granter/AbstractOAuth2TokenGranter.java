package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;

public abstract class AbstractOAuth2TokenGranter implements TokenGranter {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractOAuth2TokenGranter.class);

    private final TokenServices tokenServices;
    private final ReactiveAuthenticationManager authenticationManager;

    public AbstractOAuth2TokenGranter(TokenServices tokenServices,
                                      ReactiveAuthenticationManager authenticationManager) {
        this.tokenServices = tokenServices;
        this.authenticationManager = authenticationManager;
    }

    protected Mono<OAuth2AuthorizationRequest> authenticateUsernameAndPassword(AuthorizationRequest authorizationRequest) {
        var usernameAndPasswordToken = new UsernamePasswordAuthenticationToken(
                authorizationRequest.getAttribute(USERNAME_ATTRIBUTE),
                authorizationRequest.getAttribute(PASSWORD_ATTRIBUTE)
        );

        return getAuthenticationManager().authenticate(usernameAndPasswordToken)
                .doOnError(throwable -> Mono.error(new OAuthError(throwable, throwable.getMessage(), "error authenticating user")))
                .map(authentication -> new OAuth2AuthorizationRequest(authorizationRequest, authentication));
    }

    /**
     * Create an {@link OAuth2Authentication} token from the provided client userAuthentication and the {@link OAuth2AuthorizationRequest}
     * @param authentication client userAuthentication
     * @param authorizationRequest authorization request containing the user userAuthentication
     */
    protected OAuth2Authentication createAuthenticationToken(Authentication authentication,
                                                             OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Authentication oAuth2Authentication = OAuth2Authentication.from(authentication);
        oAuth2Authentication.setAuthorizationRequest(authorizationRequest);
        oAuth2Authentication.setAuthenticationStage(AuthenticationStage.COMPLETE);
        LOG.debug("created Authentication Token");
        return oAuth2Authentication;
    }

    protected TokenServices getTokenServices() {
        return tokenServices;
    }

    protected ReactiveAuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }
}
