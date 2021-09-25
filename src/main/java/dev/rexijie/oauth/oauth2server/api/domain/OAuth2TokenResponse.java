package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.Arrays;
import java.util.Objects;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OAuth2TokenResponse(String accessToken,
                                  String tokenType,
                                  String scope,
                                  long expiresIn,
                                  String refreshToken) {
    public static OAuth2TokenResponse fromAccessToken(OAuth2AccessToken accessToken) {
        return new OAuth2TokenResponse(accessToken.getTokenValue(),
                accessToken.getTokenType().getValue(),
                Arrays.toString(accessToken.getScopes().toArray()),
                (int) Objects.requireNonNull(accessToken.getExpiresAt()).getEpochSecond() -
                        Objects.requireNonNull(accessToken.getIssuedAt()).getEpochSecond(),
                null);
    }
}
