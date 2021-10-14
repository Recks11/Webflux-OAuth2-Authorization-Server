package dev.rexijie.oauth.oauth2server.token.granter;


import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_GRANT_ERROR;

public class ResourceOwnerPasswordCredentialsTokenGranter extends AbstractOAuth2TokenGranter {
    private static final Logger LOG = LoggerFactory.getLogger(ResourceOwnerPasswordCredentialsTokenGranter.class);

    public ResourceOwnerPasswordCredentialsTokenGranter(TokenServices tokenServices,
                                                        ReactiveAuthenticationManager authenticationManager) {
        super(tokenServices, authenticationManager);
    }

    @Override
    public Mono<Void> validateRequest(AuthorizationRequest request) {
        if (!AuthorizationGrantType.PASSWORD.equals(new AuthorizationGrantType(request.getGrantType())))
            return Mono.error(INVALID_GRANT_ERROR);
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        LOG.debug("Received request");
        return validateRequest(authorizationRequest)
                .then(authenticateUsernameAndPassword(authorizationRequest)
                        .doOnSuccess(oAuth2AuthorizationRequest ->
                                LOG.debug("authenticate user {}", authorizationRequest.getAttribute(USERNAME_ATTRIBUTE)))
                        .doOnError(throwable -> {
                            LOG.error("failed to authenticate user {}", authorizationRequest.getAttribute(USERNAME_ATTRIBUTE));
                            throw Exceptions.propagate(throwable);
                        })
                        .map(oAuth2AuthorizationRequest -> createAuthenticationToken(authentication, oAuth2AuthorizationRequest))
                        .doOnSuccess(authentication1 ->
                                LOG.debug("Created Authentication token for client {} and user {}", authentication1.getPrincipal(),
                                authentication1.getUserAuthentication().getPrincipal()))
                        .flatMap(getTokenServices()::createAccessToken));
    }
}
