package dev.rexijie.oauth.oauth2server.services;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import dev.rexijie.oauth.oauth2server.converter.TokenEnhancer;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Base64;

import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_SCOPE;

@Component
public class DefaultTokenServices implements TokenServices {

    private final ClientService clientService;
    private final UserService userService;
    private final SecretGenerator secretGenerator;

    public DefaultTokenServices(ClientService clientService,
                                UserService userService, SecretGenerator secretGenerator) {
        this.clientService = clientService;
        this.userService = userService;
        this.secretGenerator = secretGenerator;
    }

    @Override
    public OAuth2AccessToken createAccessToken(Authentication authentication,
                                               OAuth2AuthorizationRequest authorizationRequest) {
        var clientDetails = (ClientUserDetails) authentication.getPrincipal();
        var clientMetaData = clientDetails.clientData();

        if (!clientMetaData.scopes().containsAll(authorizationRequest.getScopes()))
            throw new OAuth2AuthorizationException(new OAuth2Error(INVALID_SCOPE));
        var tokenId = secretGenerator.generate(16);

        var token = new OAuth2AccessToken(BEARER,
                tokenId,
                Instant.now(),
                Instant.now().plusSeconds(getAccessTokenValiditySeconds(clientMetaData)),
                authorizationRequest.getScopes()); // TODO (modify to get scopes a user can have?)

        return getTokenEnhancer().enhance(token, authentication);
    }

    @Override
    public OAuth2Token refreshAccessToken(RefreshToken token, RefreshTokenRequest request) {
        return null;
    }

    @Override
    public OAuth2Token getAccessToken(Authentication authentication) {
        return null;
    }

    @Override
    public String decryptBasicToken(String value) {
        return new String(Base64.getDecoder().decode(value));
    }

    @Override
    public int getAccessTokenValiditySeconds(Client client) {
        return 0;
    }

    protected TokenEnhancer getTokenEnhancer() {
        return (token, auth) -> token;
    }
}
