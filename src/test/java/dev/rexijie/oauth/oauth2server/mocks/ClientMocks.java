package dev.rexijie.oauth.oauth2server.mocks;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientProfiles;
import dev.rexijie.oauth.oauth2server.model.ClientTypes;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

public class ClientMocks {
    public static Client createTestClient() {
        return new Client(
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
    }
}
