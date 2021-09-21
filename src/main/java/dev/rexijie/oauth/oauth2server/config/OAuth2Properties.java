package dev.rexijie.oauth.oauth2server.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.util.Set;

@ConstructorBinding
@ConfigurationProperties(prefix = "oauth2")
public record OAuth2Properties(OAuth2ServerProperties server,
                               OidcProperties openId
) {
    /**
     * OAuth2 Server Properties
     */
    public static record OAuth2ServerProperties(String resourceId,
                                                boolean implicitEnabled) {
    }


    /**
     * OAuth2 OpenIDConnect Properties from property source
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static record OidcProperties(@JsonIgnore
                                        String baseUri,
                                        @JsonIgnore
                                        String oauthEndpoint,
                                        String issuer,
                                        String tokenEndpoint,
                                        String tokenKeyEndpoint,
                                        String authorizationEndpoint,
                                        String checkTokenEndpoint,
                                        String userinfoEndpoint,
                                        String introspectionEndpoint,
                                        String jwksUri,
                                        String revocationEndpoint,
                                        Set<String> userinfoSigningAlgSupported,
                                        Set<String> idTokenSigningAlgValuesSupported,
                                        @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
                                        Set<String> tokenEndpointAuthSigningAlgorithmsSupported,
                                        Set<String> scopesSupported,
                                        Set<String> subjectTypesSupported,
                                        Set<String> responseTypesSupported,
                                        Set<String> claimsSupported,
                                        Set<String> grantTypesSupported,
                                        Set<String> tokenEndpointAuthMethodsSupported) {
    }
}
