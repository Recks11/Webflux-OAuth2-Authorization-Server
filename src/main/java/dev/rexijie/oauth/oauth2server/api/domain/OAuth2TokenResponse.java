package dev.rexijie.oauth.oauth2server.api.domain;

record OAuth2TokenResponse(ClientCredentials accessToken,
                           ClientCredentials tokenType,
                           ClientCredentials scope,
                           int expiresIn,
                           ClientCredentials refreshToken) {
}
