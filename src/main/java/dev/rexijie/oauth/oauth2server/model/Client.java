package dev.rexijie.oauth.oauth2server.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

// TODO - Use some client object fields in token generation
@Document
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Client(
        @Id
        String id,
        @NotBlank(message = "Name cannot be blank") String clientName,
        String clientType,
        String clientProfile,
        String clientId,
        String clientSecret,
        @Min(value = 1, message = "clients must have at least 1 scope") Set<String> scopes,
        @Min(value = 1, message = "clients must have at least 1 resourceId") Set<String> resourceIds,
        @Min(value = 1, message = "clients must have at least 1 grant type") Set<String> authorizedGrantTypes,
        @Min(value = 1, message = "clients must have at least 1 redirectUris") Set<String> registeredRedirectUris,
        @Min(value = 1, message = "clients must provide a set of authorities") Set<String> authorities,
        int accessTokenValidity,
        int refreshTokenValidity,
        Map<String, Object> additionalInfo,
        String logoUri,
        String clientUri, // uri to the homepage of the client;
        String policyUri,
//     String jwksUri,
//     String jwks,
        String selectorIdentifierUri, // json file showing alternate redirect uris
        String subjectTypes, // subject types supported to use for requests to this client
        String tokenEndpointAuthMethod,
        int defaultMaxAge, // default value for max_age claim
        boolean requireAuthTime, // is auth time claim required?
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {


    @Override
    public String toString() {
        return "Client {" +
                "id: '" + id() + '\'' +
                ", name: '" + clientName() + '\'' +
                ", type: '" + clientType() + '\'' +
                ", clientId: '" + this.clientId() + '\'' +
                ", clientSecret: '" + "[SECRET]" + '\'' +
                ", scope: '" + this.scopes() + '\'' +
                ", resourceIds: '" + this.resourceIds() + '\'' +
                ", authorizedGrantTypes: '" + this.authorizedGrantTypes() + '\'' +
                ", registeredRedirectUris: '" + this.registeredRedirectUris() + '\'' +
                ", authorities: '" + this.authorities() + '\'' +
                ", accessTokenValiditySeconds: '" + this.accessTokenValidity() + '\'' +
                ", refreshTokenValiditySeconds: '" + this.refreshTokenValidity() + '\'' +
                ", additionalInformation: '" + this.additionalInfo() + '\'' +
                ", createdAt: '" + createdAt() + '\'' +
                ", updatedAt: '" + updatedAt() + '\'' +
                "}";
    }
}
