package dev.rexijie.oauth.oauth2server.token.granter;


import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.AuthorizationTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
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
    public Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest request) {
        if (!AuthorizationGrantType.PASSWORD.equals(new AuthorizationGrantType(request.getGrantType())))
            return Mono.error(INVALID_GRANT_ERROR);
        return Mono.just(request);
    }

    @Override
    public Mono<AuthorizationTokenResponse> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        LOG.debug("Received request");
        return validateRequest(authentication, authorizationRequest)
                .flatMap(req -> authenticateUsernameAndPassword(req)
                        .doOnSuccess(oAuth2AuthorizationRequest ->
                                LOG.debug("authenticate user {}", authorizationRequest.getAttribute(USERNAME_ATTRIBUTE)))
                        .doOnError(throwable -> {
                            LOG.error("failed to authenticate user {}", authorizationRequest.getAttribute(USERNAME_ATTRIBUTE));
                            throw Exceptions.propagate(throwable);
                        })
                        .map(oAuth2AuthorizationRequest -> createAuthenticationToken(authentication, oAuth2AuthorizationRequest))
                        .doOnSuccess(fullAuthentication ->
                                LOG.debug("Created Authentication token for client {} and user {}", fullAuthentication.getPrincipal(),
                                        fullAuthentication.getUserAuthentication().getPrincipal()))
                        .flatMap(this::grantTokensFromAuthentication));
    }
}
