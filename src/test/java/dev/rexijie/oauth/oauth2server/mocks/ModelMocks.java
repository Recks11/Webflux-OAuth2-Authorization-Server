package dev.rexijie.oauth.oauth2server.mocks;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientProfiles;
import dev.rexijie.oauth.oauth2server.model.ClientTypes;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.authority.Authority;
import dev.rexijie.oauth.oauth2server.model.authority.AuthorityEnum;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class ModelMocks {
    public static Client testClient() {
        return testClient("test-client", "secret");
    }
    public static Client testClient(String clientId, String secret) {
        return new Client(
                UUID.randomUUID().toString(),
                "Test client",
                ClientTypes.PUBLIC.toString(),
                ClientProfiles.WEB.toString(),
                clientId,
                secret,
                Set.of("read","write","read:profile"),
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

    public static User testUser() {
        return testUser("encoded-password");
    }
    public static User testUser(String password) {
        return new User(
                "rexijie",
                password,
                "gisBae@rexijie.dev",
                Set.of(new Authority("ADMIN"),
                        new Authority(AuthorityEnum.CAN_CREATE),
                        new Authority(AuthorityEnum.CAN_DELETE),
                        new Authority(AuthorityEnum.CAN_MODIFY),
                        new Authority(AuthorityEnum.CAN_VIEW)
                )
        );
    }
}
