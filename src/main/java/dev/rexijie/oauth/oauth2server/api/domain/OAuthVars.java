package dev.rexijie.oauth.oauth2server.api.domain;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

public class OAuthVars {
    public static class RequestParameterNames implements OAuth2ParameterNames {}
    public static class GrantTypes {
        public static final String CLIENT_CREDENTIALS = "client_credentials";
        public static final String AUTHORIZATION_CODE = "authorization_code";
        public static final String IMPLICIT = "implicit";
        public static final String PASSWORD = "password";
        public static final String REFRESH_TOKEN = "refresh_token";
        public static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    }
}
