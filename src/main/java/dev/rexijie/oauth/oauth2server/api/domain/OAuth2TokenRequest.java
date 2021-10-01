package dev.rexijie.oauth.oauth2server.api.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuth2TokenRequest {
    private final String grantType;
    private final String code;
    private final String redirectUri;
    private final String clientId;

    public OAuth2TokenRequest(String grantType, String code, String redirectUri, String clientId) {
        this.grantType = grantType;
        this.code = code;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
    }

}
