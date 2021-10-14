package dev.rexijie.oauth.oauth2server.mocks;

import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientProfiles;
import dev.rexijie.oauth.oauth2server.model.ClientTypes;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.authority.Authority;
import dev.rexijie.oauth.oauth2server.model.authority.AuthorityEnum;
import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
import org.springframework.security.core.token.TokenService;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static dev.rexijie.oauth.oauth2server.model.dto.ClientDTO.ClientMapper.toDto;

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
                Set.of("read", "write", "read:profile"),
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
                "client_secret_basic",
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


    public static Client getDefaultClient(String password) {
        return ModelMocks.testClient("test-client", password);
    }

    public static User getDefaultUser(String password) {
        User testUser = ModelMocks.testUser(password);
        testUser.setAccountNonLocked(true);
        testUser.setEnabled(true);
        testUser.setAccountNonExpired(true);
        testUser.setCredentialsNonExpired(true);
        return testUser;
    }

    public static class Authentication {
        public static OAuth2Authentication mockUserAuthentication(User user) {
            var authentication = new OAuth2Authentication(
                    user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities()
            );
            authentication.setAuthenticated(true);
            authentication.setAuthenticationStage(AuthenticationStage.STARTED);
            authentication.setAuthorizationRequest(null);
            authentication.setDetails(UserDTO.UserDTOMapper.toDto(user));
            return authentication;
        }

        public static OAuth2Authentication createClientAuthentication(Client client) {

            var authentication = new OAuth2Authentication(
                    client.clientId(),
                    client.clientSecret(),
                    client.authorities().stream().map(Authority::new).collect(Collectors.toSet())
            );
            authentication.setAuthenticated(true);
            authentication.setAuthenticationStage(AuthenticationStage.STARTED);
            authentication.setAuthorizationRequest(null);
            authentication.setDetails(toDto(ModelMocks.testClient()));
            return authentication;
        }
    }
}
