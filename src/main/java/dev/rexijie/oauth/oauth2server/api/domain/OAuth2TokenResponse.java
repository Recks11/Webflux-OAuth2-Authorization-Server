package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuth2TokenResponse implements Serializable {
    private String accessToken;
    private String tokenType;
    private String scope;
    private long expiresIn;
    private String refreshToken;

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

    public static OAuth2TokenResponse fromAccessToken(OAuth2AccessToken accessToken) {
        String scopes = "";
        for (String scope :
                accessToken.getScopes()) {
            scopes = scopes.concat(scope + " ");
        }
        scopes = scopes.trim();
        return new OAuth2TokenResponse(accessToken.getTokenValue(),
                accessToken.getTokenType().getValue(),
                scopes,
                (int) Objects.requireNonNull(accessToken.getExpiresAt()).getEpochSecond() -
                        Objects.requireNonNull(accessToken.getIssuedAt()).getEpochSecond(),
                null);
    }
}
