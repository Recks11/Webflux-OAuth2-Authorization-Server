package dev.rexijie.oauth.oauth2server.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.model.Client;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
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
    private String clientUri;
    private String selectorIdentifierUri;
    private String subjectTypes;
    //    String tokenEndpointAuthenticationMethod;
    private int defaultMaxAge;

    public ClientDTO() {
    }

    public ClientDTO(String clientName, String clientType,
                     Set<String> scopes, Set<String> resourceIds, Set<String> grantTypes,
                     Set<String> redirectUris, Set<String> authorities,
                     String clientProfile, String logoUri,
                     String clientUri, String selectorIdentifierUri,
                     String subjectTypes, int defaultMaxAge) {
        this.clientName = clientName;
        this.clientType = clientType;
        this.scopes = scopes;
        this.resourceIds = resourceIds;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.authorities = authorities;
        this.clientProfile = clientProfile;
        this.logoUri = logoUri;
        this.clientUri = clientUri;
        this.selectorIdentifierUri = selectorIdentifierUri;
        this.subjectTypes = subjectTypes;
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

    public String getClientUri() {
        return clientUri;
    }

    public String getSelectorIdentifierUri() {
        return selectorIdentifierUri;
    }

    public String getSubjectTypes() {
        return subjectTypes;
    }

    public int getDefaultMaxAge() {
        return defaultMaxAge;
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
                    client.clientUri(),
                    client.selectorIdentifierUri(),
                    client.subjectTypes(),
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
                    null,
                    clientDTO.defaultMaxAge,
                    false,
                    null,
                    null
            );
        }

        public static Client toClient(ClientDTO clientDTO) {
            return toClient(clientDTO, null, null);
        }

        public static Client withCredentials(Client client, ClientCredentials credentials) {
            return new Client(
                    null,
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
                    LocalDateTime.now()
            );
        }
    }
}
