package dev.rexijie.oauth.oauth2server.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ClientDTO {
    private String clientName;
    private String clientType;
    private Set<String> scopes;
    private Set<String> resourceIds;
    private Set<String> grantTypes;
    private Set<String> redirectUris;
    private Set<String> authorities;
    private String clientProfile;
    private String logoUri;
    private int accessTokenValidity;
    private int refreshTokenValidity;
    private String clientUri;
    private String selectorIdentifierUri;
    private String subjectTypes;
    private String tokenEndpointAuthenticationMethod;
    private int defaultMaxAge;

    public ClientDTO() {
    }

    public ClientDTO(String clientName, String clientType,
                     Set<String> scopes, Set<String> resourceIds, Set<String> grantTypes,
                     Set<String> redirectUris, Set<String> authorities,
                     String clientProfile, String logoUri, int accessTokenValidity, int refreshTokenValidity,
                     String clientUri, String selectorIdentifierUri,
                     String subjectTypes, String tokenEndpointAuthenticationMethod,
                     int defaultMaxAge) {
        this.clientName = clientName;
        this.clientType = clientType;
        this.scopes = scopes;
        this.resourceIds = resourceIds;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.authorities = authorities;
        this.clientProfile = clientProfile;
        this.logoUri = logoUri;
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
        this.clientUri = clientUri;
        this.selectorIdentifierUri = selectorIdentifierUri;
        this.subjectTypes = subjectTypes;
        this.tokenEndpointAuthenticationMethod = tokenEndpointAuthenticationMethod;
        this.defaultMaxAge = defaultMaxAge;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientType() {
        return clientType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Set<String> getResourceIds() {
        return resourceIds;
    }

    public Set<String> getGrantTypes() {
        return grantTypes;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public String getClientProfile() {
        return clientProfile;
    }

    public String getLogoUri() {
        return logoUri;
    }

    public int getAccessTokenValidity() {
        return accessTokenValidity;
    }

    public int getRefreshTokenValidity() {
        return refreshTokenValidity;
    }

    public String getClientUri() {
        return clientUri;
    }

    public String getSelectorIdentifierUri() {
        return selectorIdentifierUri;
    }

    public String getSubjectTypes() {
        return subjectTypes;
    }

    public String getTokenEndpointAuthenticationMethod() {
        return tokenEndpointAuthenticationMethod;
    }

    public int getDefaultMaxAge() {
        return defaultMaxAge;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientDTO clientDTO = (ClientDTO) o;
        return getDefaultMaxAge() == clientDTO.getDefaultMaxAge() &&
                Objects.equals(getClientName(), clientDTO.getClientName()) &&
                Objects.equals(getClientType(), clientDTO.getClientType()) &&
                Objects.equals(getScopes(), clientDTO.getScopes()) &&
                Objects.equals(getResourceIds(), clientDTO.getResourceIds()) &&
                Objects.equals(getGrantTypes(), clientDTO.getGrantTypes()) &&
                Objects.equals(getRedirectUris(), clientDTO.getRedirectUris()) &&
                Objects.equals(getAuthorities(), clientDTO.getAuthorities()) &&
                Objects.equals(getClientProfile(), clientDTO.getClientProfile()) &&
                Objects.equals(getAccessTokenValidity(), clientDTO.getAccessTokenValidity()) &&
                Objects.equals(getRefreshTokenValidity(), clientDTO.getRefreshTokenValidity()) &&
                Objects.equals(getLogoUri(), clientDTO.getLogoUri()) &&
                Objects.equals(getClientUri(), clientDTO.getClientUri()) &&
                Objects.equals(getSelectorIdentifierUri(), clientDTO.getSelectorIdentifierUri()) &&
                Objects.equals(getSubjectTypes(), clientDTO.getSubjectTypes()) &&
                Objects.equals(getTokenEndpointAuthenticationMethod(), clientDTO.getTokenEndpointAuthenticationMethod());
    }

    public static class ClientMapper {
        public static ClientDTO toDto(Client client) {
            return new ClientDTO(
                    client.clientName(),
                    client.clientType(),
                    client.scopes(),
                    client.resourceIds(),
                    client.authorizedGrantTypes(),
                    client.registeredRedirectUris(),
                    client.authorities(),
                    client.clientProfile(),
                    client.logoUri(),
                    client.accessTokenValidity(),
                    client.refreshTokenValidity(),
                    client.clientUri(),
                    client.selectorIdentifierUri(),
                    client.subjectTypes(),
                    client.tokenEndpointAuthMethod(),
                    client.defaultMaxAge()
            );
        }

        public static Client toClient(ClientDTO clientDTO, String clientId, String clientSecret) {
            return new Client(
                    null,
                    clientDTO.clientName,
                    clientDTO.clientType,
                    clientDTO.clientProfile,
                    clientId,
                    clientSecret,
                    clientDTO.scopes,
                    clientDTO.resourceIds,
                    clientDTO.grantTypes,
                    clientDTO.redirectUris,
                    clientDTO.authorities,
                    36,
                    3600,
                    Map.of(),
                    clientDTO.logoUri,
                    clientDTO.clientUri,
                    null,
                    clientDTO.selectorIdentifierUri,
                    clientDTO.subjectTypes,
                    clientDTO.tokenEndpointAuthenticationMethod,
                    clientDTO.defaultMaxAge,
                    false,
                    0,
                    0
            );
        }

        public static Client toClient(ClientDTO clientDTO) {
            return toClient(clientDTO, null, null);
        }

        public static Client withCredentials(Client client, ClientCredentials credentials) {
            return new Client(
                    client.id(),
                    client.clientName(),
                    client.clientType(),
                    client.clientProfile(),
                    credentials.clientId(),
                    credentials.clientSecret(),
                    client.scopes(),
                    client.resourceIds(),
                    client.authorizedGrantTypes(),
                    client.registeredRedirectUris(),
                    client.authorities(),
                    client.accessTokenValidity(),
                    client.refreshTokenValidity(),
                    client.additionalInfo(),
                    client.logoUri(),
                    client.clientUri(),
                    client.policyUri(),
                    client.selectorIdentifierUri(),
                    client.subjectTypes(),
                    client.tokenEndpointAuthMethod(),
                    client.defaultMaxAge(),
                    client.requireAuthTime(),
                    client.createdAt(),
                    TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now())
            );
        }
    }
}
