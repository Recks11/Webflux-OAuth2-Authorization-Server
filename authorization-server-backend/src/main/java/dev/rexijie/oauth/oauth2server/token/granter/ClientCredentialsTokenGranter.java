package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.CLIENT_AUTHENTICATION_METHOD;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_GRANT_ERROR;

public class ClientCredentialsTokenGranter extends AbstractOAuth2TokenGranter {

    public ClientCredentialsTokenGranter(TokenServices tokenServices,
                                         ReactiveAuthenticationManager authenticationManager) {
        super(tokenServices, authenticationManager);
    }

    @Override
    public Mono<AuthorizationRequest> validateRequest(Authentication authentication, AuthorizationRequest request) {
        if (!new AuthorizationGrantType(request.getGrantType()).equals(AuthorizationGrantType.CLIENT_CREDENTIALS))
            return Mono.error(INVALID_GRANT_ERROR);
        return Mono.just(request);
    }

    @Override
    public Mono<OAuth2Token> grantToken(Authentication authentication, AuthorizationRequest authorizationRequest) {
        return validateRequest(authentication, authorizationRequest)
                .map(validRequest -> createAuthenticationToken(authentication,
                        new OAuth2AuthorizationRequest(authorizationRequest, authentication)))
                .flatMap(credentials -> getTokenServices().createAccessToken(credentials));
    }

    @Override
    protected OAuth2Authentication createAuthenticationToken(Authentication authentication,
                                                             OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Authentication oAuth2Authentication = OAuth2Authentication.from(authentication);
        oAuth2Authentication.setAuthenticationStage(AuthenticationStage.COMPLETE);
        // TODO make sure to validate authReqyest and passed reqyest
//        if (oAuth2Authentication.getStoredRequest().equals(authorizationRequest.storedRequest())) {
            oAuth2Authentication.setAuthorizationRequest(authorizationRequest);
//        }

        return oAuth2Authentication;

    }
}
