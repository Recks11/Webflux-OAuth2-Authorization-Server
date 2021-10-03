package dev.rexijie.oauth.oauth2server.services;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.enhancer.TokenEnhancer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

@Component
public class DefaultTokenServices implements TokenServices {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenServices.class);

    private final ClientService clientService;
    private final TokenEnhancer tokenEnhancer;
    private final TokenService tokenService;

    public DefaultTokenServices(ClientService clientService,
                                TokenEnhancer tokenEnhancer,
                                TokenService tokenService) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.tokenEnhancer = tokenEnhancer;
    }



    /**
     * Create an access token from an authenticated client provided an authorization request
     *
     * @param authentication       client userAuthentication
     */
    @Override
    public Mono<OAuth2Token> createAccessToken(Authentication authentication) {
        var auth2Authentication = (OAuth2Authentication) authentication;
        var clientMetaData = (ClientDTO) authentication.getDetails();

        if (!clientMetaData.getScopes().containsAll(auth2Authentication.getStoredRequest().getScopes()))
            return Mono.error(INVALID_SCOPE_ERROR);

        Token token = generateToken(authentication);

        var oauthToken = new OAuth2AccessToken(BEARER,
                token.getKey(),
                Instant.now(),
                Instant.now().plusSeconds(clientMetaData.getAccessTokenValidity()),
                auth2Authentication.getStoredRequest().getScopes()); // TODO (modify to get scopes a user can have?)

        return getTokenEnhancer().enhance(oauthToken, authentication);
    }

    @Override
    public Mono<OAuth2Token> refreshAccessToken(RefreshToken token, RefreshTokenRequest request) {
        // read userAuthentication from access token,
        // use it to regenerate token
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2Token> getAccessToken(Authentication authentication) {
        return Mono.empty();
    }

    private String generateTokenAdditionalInformation(Authentication authentication) {
        return "username=%s".formatted(authentication.getPrincipal());
    }

    protected TokenEnhancer getTokenEnhancer() {
        return this.tokenEnhancer;
    }

    private Token generateToken(Authentication authentication) {
        var auth2Authentication = (OAuth2Authentication) authentication;
        var authorizationRequest = auth2Authentication.getAuthorizationRequest();
        Authentication userAuthentication = authorizationRequest.userAuthentication();

        return tokenService.allocateToken(generateTokenAdditionalInformation(userAuthentication));
    }
}
