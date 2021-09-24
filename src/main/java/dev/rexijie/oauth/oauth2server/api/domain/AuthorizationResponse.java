package dev.rexijie.oauth.oauth2server.api.domain;

public record AuthorizationResponse(String code,
                                    String state) {
}
