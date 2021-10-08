package dev.rexijie.oauth.oauth2server.services.token;

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

import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_CLIENT_ERROR;
import static dev.rexijie.oauth.oauth2server.error.OAuthError.INVALID_SCOPE_ERROR;
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
            var clientId = authentication.getPrincipal().toString();
            var userId = clientAuthentication.getUserPrincipal().toString();
            return clientService.findClientById(clientId)
                    .zipWith(userService.findUserByUsername(userId), (clientDTO, userDTO) -> {
                        clientAuthentication.setDetails(clientDTO);
                        var userAuthentication = (OAuth2Authentication) clientAuthentication.getUserAuthentication();
                        userAuthentication.setDetails(userDTO);
                        if (!clientDTO.getScopes().containsAll(clientAuthentication.getStoredRequest().getScopes()))
                            throw Exceptions.propagate(INVALID_SCOPE_ERROR);
                        return clientAuthentication;
                    }).flatMap(auth -> {
                        Token token = generateToken(authentication);
                        var clientData = (ClientDTO) auth.getDetails();
                        var oauthToken = new OAuth2AccessToken(BEARER,
                                token.getKey(),
                                Instant.now(),
                                Instant.now().plusSeconds(clientData.getAccessTokenValidity()),
                                clientAuthentication.getStoredRequest().getScopes()); // TODO (modify to get scopes a user can have?)
                        LOG.debug("crating access token");
                        return getTokenEnhancer().enhance(oauthToken, authentication);
                    });
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
