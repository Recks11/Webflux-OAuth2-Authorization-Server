package dev.rexijie.oauth.oauth2server.converter;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtGeneratingTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken token, Authentication authentication) {

        Jwt.withTokenValue(token.getTokenValue())
                .issuedAt(token.getIssuedAt())
                .expiresAt(token.getExpiresAt())
                .subject(extractUsernameFromAuthentication(authentication));
        return null;
    }

    private String extractUsernameFromAuthentication(Authentication authentication) {
        return "username";
    }
}
