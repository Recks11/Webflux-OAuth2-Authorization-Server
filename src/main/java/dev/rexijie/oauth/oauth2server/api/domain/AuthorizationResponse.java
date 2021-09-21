package dev.rexijie.oauth.oauth2server.api.domain;

public record AuthorizationResponse(ClientCredentials code,
                                    ClientCredentials state) {
}
