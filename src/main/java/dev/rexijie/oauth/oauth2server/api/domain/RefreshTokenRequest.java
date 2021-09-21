package dev.rexijie.oauth.oauth2server.api.domain;

public record RefreshTokenRequest(ClientCredentials grantType,
                                  ClientCredentials refreshToken,
                                  ClientCredentials scope) {
}
