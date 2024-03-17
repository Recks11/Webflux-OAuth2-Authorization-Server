package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record RefreshTokenRequest(String grantType,
                                  String refreshToken,
                                  String scope) {
}
