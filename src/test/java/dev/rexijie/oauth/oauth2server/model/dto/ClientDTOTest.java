package dev.rexijie.oauth.oauth2server.model.dto;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientProfiles;
import dev.rexijie.oauth.oauth2server.model.ClientTypes;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ClientDTOTest {
    Client client = new Client(
            null,
            "Test client",
            ClientTypes.PUBLIC.toString(),
            ClientProfiles.WEB.toString(),
            null,
            null,
            Set.of("read"),
            Set.of("OAuthServer"),
            Set.of("authorization_code", "implicit"),
            Set.of("http://localhost:8081/oauth/code"),
            Set.of("ROLE_USER", "ROLE_ADMIN"),
            36,
            3600,
            Map.of(),
            "http://localhost:8080/favicon.png",
            "httpL//localhost:8080/",
            null,
            "http://localhost:8080/meta/redirects.json",
            "",
            null,
            3600,
            false,
            TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()),
            TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now())
    );

    @Test
    void canMapToDto() {

        var dto = ClientDTO.ClientMapper.toDto(client);
        assertEquals(client.clientName(), dto.getClientName());
        assertEquals(client.clientType(), dto.getClientType());
        assertEquals(client.clientProfile(), dto.getClientProfile());
        assertEquals(client.scopes(), dto.getScopes());
        assertEquals(client.resourceIds(), dto.getResourceIds());
        assertEquals(client.authorizedGrantTypes(), dto.getGrantTypes());
        assertEquals(client.registeredRedirectUris(), dto.getRedirectUris());
        assertEquals(client.authorities(), dto.getAuthorities());
        assertEquals(client.logoUri(), dto.getLogoUri());
        assertEquals(client.clientUri(), dto.getClientUri());
        assertEquals(client.selectorIdentifierUri(), dto.getSelectorIdentifierUri());
        assertEquals(client.subjectTypes(), dto.getSubjectTypes());
        assertEquals(client.defaultMaxAge(), dto.getDefaultMaxAge());
    }

    void canAddClientIdAndSecret() {
        var dto = ClientDTO.ClientMapper.toDto(client);
        var cli = ClientDTO.ClientMapper.toClient(dto);
        assertNull(cli.clientId());
        assertNull(cli.clientSecret());
        var clis = ClientDTO.ClientMapper.toClient(dto, "clientid", "secret");
        assertEquals("clientid", clis.clientId());
        assertEquals("secret", clis.clientSecret());
    }

}