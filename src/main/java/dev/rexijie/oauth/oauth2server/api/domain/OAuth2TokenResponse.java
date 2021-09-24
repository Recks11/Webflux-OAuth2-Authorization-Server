package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
record OAuth2TokenResponse(String accessToken,
                           String tokenType,
                           String scope,
                           int expiresIn,
                           String refreshToken) {
}
