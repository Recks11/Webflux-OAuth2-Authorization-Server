package dev.rexijie.oauth.oauth2server.services;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import dev.rexijie.oauth.oauth2server.api.domain.RefreshTokenRequest;
import dev.rexijie.oauth.oauth2server.converter.TokenEnhancer;
import dev.rexijie.oauth.oauth2server.model.Client;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

@Component
public interface TokenServices {
    OAuth2Token createAccessToken(Authentication authentication, OAuth2AuthorizationRequest authorizationRequest);
    OAuth2Token refreshAccessToken(RefreshToken token, RefreshTokenRequest request);
    OAuth2Token getAccessToken(Authentication authentication);
    String decryptBasicToken(String value);
    int getAccessTokenValiditySeconds(Client client);
}
