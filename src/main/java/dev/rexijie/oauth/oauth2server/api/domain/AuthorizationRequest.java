package dev.rexijie.oauth.oauth2server.api.domain;

public record AuthorizationRequest(ClientCredentials responseType,
                                   ClientCredentials clientId,
                                   ClientCredentials redirectUri,
                                   ClientCredentials scope,
                                   ClientCredentials state) {
}
