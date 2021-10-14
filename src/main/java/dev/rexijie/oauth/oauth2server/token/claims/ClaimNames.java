package dev.rexijie.oauth.oauth2server.token.claims;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

public class ClaimNames {
    public static class OidcStandard implements StandardClaimNames {}
    public static class IDToken implements IdTokenClaimNames {}
    public static class JWT implements JwtClaimNames {}
    public static class Introspection implements OAuth2IntrospectionClaimNames {}
    public static class Custom {
        public static final String SCOPES = "scopes";
        public static final String AUTHORITIES = "authorities";
        public static final String AUTHORIZATION_REQUEST = "authorizationRequest";
    }
}
