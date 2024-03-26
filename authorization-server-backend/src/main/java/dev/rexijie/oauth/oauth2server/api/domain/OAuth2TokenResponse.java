package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import dev.rexijie.oauth.oauth2server.token.AuthorizationTokenResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuth2TokenResponse implements Serializable {
    private String accessToken;
    private String tokenType;
    private String scope;
    private long expiresIn;
    private String refreshToken;

    public OAuth2TokenResponse() {}

    public OAuth2TokenResponse(String accessToken, String tokenType, String scope, long expiresIn, String refreshToken) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.scope = scope;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public static OAuth2TokenResponse fromAuthorizationTokenResponse(AuthorizationTokenResponse tokenResponse) {
        var accessToken = tokenResponse.accessToken();
        return new OAuth2TokenResponse(tokenResponse.accessToken().getTokenValue(),
                OAuth2AccessToken.TokenType.BEARER.getValue(),
                StringUtils.collectionToDelimitedString(tokenResponse.scopes(), " "),
                (int) Objects.requireNonNull(accessToken.getExpiresAt()).getEpochSecond() -
                        Objects.requireNonNull(accessToken.getIssuedAt()).getEpochSecond(),
                tokenResponse.refreshToken().map(OAuth2Token::getTokenValue).orElse(null));
    }
}
