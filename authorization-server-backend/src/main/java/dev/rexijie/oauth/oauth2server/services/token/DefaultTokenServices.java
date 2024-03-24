package dev.rexijie.oauth.oauth2server.services.token;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.services.user.UserService;
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
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.*;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

@Component
public class DefaultTokenServices implements TokenServices {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenServices.class);

    private final ClientService clientService;
    private final UserService userService;
    private final TokenEnhancer tokenEnhancer;
    private final TokenService tokenService;

    public DefaultTokenServices(ClientService clientService,
                                UserService userService,
                                TokenEnhancer tokenEnhancer,
                                TokenService tokenService) {
        this.clientService = clientService;
        this.userService = userService;
        this.tokenService = tokenService;
        this.tokenEnhancer = tokenEnhancer;
    }


    /**
     * Create an access token from an authenticated client provided an authorization request
     * the authentication passed must be a {@link OAuth2Authentication} containing the client authentication
     *
     * @param authentication client authentication
     */
    @Override
    public Mono<OAuth2Token> createAccessToken(Authentication authentication) {
        if (authentication instanceof OAuth2Authentication clientAuthentication) {
            try {
                var reqGrant = clientAuthentication.getStoredRequest().getGrantType();
                var grantType = GrantType.parse(reqGrant);
                if (grantType.equals(CLIENT_CREDENTIALS)) {
                    return createClientCredentialsToken(clientAuthentication)
                            .doOnSuccess(auth2Token -> LOG.info("created client credentials token"));
                }

                var clientId = authentication.getPrincipal().toString();
                var userId = clientAuthentication.getUserPrincipal().toString();

                return createUserToken(clientId, userId, clientAuthentication)
                        .doOnSuccess(auth2Token -> LOG.info("created user access token"));
            } catch (ParseException e) {
                throw Exceptions.propagate(INVALID_GRANT_ERROR);
            }
        }
        return Mono.error(INVALID_CLIENT_ERROR);
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

    @Override
    public Mono<OAuth2Authentication> readAuthentication(OAuth2Token auth2Token, OAuth2Authentication authentication) {
        return getTokenEnhancer().isEnhanced(auth2Token)
                .flatMap(aBoolean -> {
                    if (aBoolean) return getTokenEnhancer().readAuthentication(auth2Token, authentication);
                    else return Mono.empty();
                });
    }

    private String generateTokenAdditionalInformation(Authentication authentication) {
        return "username=%s".formatted(authentication.getPrincipal());
    }

    private Token generateToken(Authentication authentication) {
        var auth2Authentication = (OAuth2Authentication) authentication;
        var authorizationRequest = auth2Authentication.getAuthorizationRequest();
        Authentication userAuthentication = authorizationRequest.userAuthentication();

        return tokenService.allocateToken(generateTokenAdditionalInformation(userAuthentication));
    }

    private Mono<OAuth2Token> createClientCredentialsToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = createAccessToken(authentication);
        return getTokenEnhancer().enhance(accessToken, authentication);
    }

    // TODO - refresh token here?
    private Mono<OAuth2Token> createUserToken(String clientId, String userId, OAuth2Authentication clientAuthentication) {
        return clientService.findClientById(clientId)
                .zipWith(userService.findUserByUsername(userId), (clientDTO, userDTO) -> {
                    clientAuthentication.setDetails(clientDTO);
                    var userAuthentication = (OAuth2Authentication) clientAuthentication.getUserAuthentication();
                    userAuthentication.setDetails(userDTO);
                    if (!clientDTO.getScopes().containsAll(clientAuthentication.getStoredRequest().getScope()))
                        throw Exceptions.propagate(INVALID_SCOPE_ERROR);
                    return clientAuthentication;
                })
                .flatMap(auth -> {
                    var oauthToken = createAccessToken(auth);
                    return getTokenEnhancer().enhance(oauthToken, auth);
                });
    }

    private OAuth2AccessToken createAccessToken(OAuth2Authentication auth) {
        LOG.debug("crating access token");
        Token token = generateToken(auth);
        var clientData = auth.getDetails(ClientDTO.class);
        return new OAuth2AccessToken(BEARER,
                token.getKey(),
                Instant.now(),
                Instant.now().plusSeconds(clientData.getAccessTokenValidity()),
                auth.getStoredRequest().getScope());
    }

    protected TokenEnhancer getTokenEnhancer() {
        return this.tokenEnhancer;
    }
}
