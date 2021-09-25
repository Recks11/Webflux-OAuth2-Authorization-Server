package dev.rexijie.oauth.oauth2server.services;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.converter.TokenEnhancer;
import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
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
    private final TokenService tokenService;
    private final OAuth2Properties.OAuth2ServerProperties oAuth2Properties;

    public DefaultTokenServices(ClientService clientService,
                                OAuth2Properties oAuth2Properties) {
        this.clientService = clientService;
        this.oAuth2Properties = oAuth2Properties.server();
        this.tokenService = tryEnhanceTokenService();
    }

    TokenService tryEnhanceTokenService() {
        try {
            var secureRandom = new SecureRandomFactoryBean().getObject();
            var toS = new KeyBasedPersistenceTokenService();
            toS.setSecureRandom(secureRandom);
            toS.setServerInteger(oAuth2Properties.hashCode());
            return toS;
        } catch (Exception ex) {
            LOG.error("Error enhancing tokenService: {}", ex.getMessage());
            return new KeyBasedPersistenceTokenService();
        }
    }

    /**
     * Create an access token from an authenticated client provided an authorization request
     *
     * @param authentication       client authentication
     * @param authorizationRequest authorization request including the user authentication
     */
    @Override
    public Mono<OAuth2Token> createAccessToken(Authentication authentication,
                                               OAuth2AuthorizationRequest authorizationRequest) {
        var clientDetails = (ClientUserDetails) authentication.getPrincipal();
        var clientMetaData = clientDetails.clientData();

        if (!clientMetaData.scopes().containsAll(authorizationRequest.storedRequest().getScopes()))
            return Mono.error(INVALID_SCOPE_ERROR);

        String username = authorizationRequest.authentication().getName();

        var tokenId = tokenService.allocateToken(username).getKey();

        var token = new OAuth2AccessToken(BEARER,
                tokenId,
                Instant.now(),
                Instant.now().plusSeconds(clientMetaData.accessTokenValidity()),
                authorizationRequest.storedRequest().getScopes()); // TODO (modify to get scopes a user can have?)

        return getTokenEnhancer().enhance(token, authentication);
    }

    @Override
    public Mono<OAuth2Token> refreshAccessToken(RefreshToken token, RefreshTokenRequest request) {
        // read authentication from access token,
        // use it to regenerate token
        return null;
    }

    @Override
    public Mono<OAuth2Token> getAccessToken(Authentication authentication) {
        return Mono.empty();
    }

    protected TokenEnhancer getTokenEnhancer() {
        return (token, auth) -> Mono.just(token);
    }
}
