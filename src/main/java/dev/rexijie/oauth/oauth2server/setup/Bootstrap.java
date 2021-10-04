package dev.rexijie.oauth.oauth2server.setup;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.ClientProfiles;
import dev.rexijie.oauth.oauth2server.model.ClientTypes;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.authority.Authority;
import dev.rexijie.oauth.oauth2server.model.authority.AuthorityEnum;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.util.TimeUtils;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@Component
@Profile("dev")
public class Bootstrap implements ApplicationListener<ApplicationStartedEvent> {
    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final AuthorizationCodeRepository authorizationCodeServices;

    public Bootstrap(ClientRepository clientRepository, UserRepository userRepository, PasswordEncoder encoder,
                     AuthorizationCodeRepository authorizationCodeServices) {
        this.clientRepository = clientRepository;
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {
        userRepository.deleteAll().block();
        clientRepository.deleteAll().block();
        userRepository.save(defaultUser()).block();
        clientRepository.save(defaultClient()).block();
        authorizationCodeServices.deleteAll().block();
    }

    private Client defaultClient() {
        return new Client(
                "client-001",
                "Test client",
                ClientTypes.CONFIDENTIAL.getName(),
                ClientProfiles.WEB.toString(),
                "test-client",
                encoder.encode("secret"),
                Set.of("read", "write"),
                Set.of("OAuthServer"),
                Set.of("authorization_code", "implicit"),
                Set.of("http://localhost:8081/oauth/code"),
                Set.of("USER", "ADMIN"),
                900,
                3600,
                Map.of(),
                "http://localhost:8080/favicon.png",
                "httpL//localhost:8080/",
                null,
                "http://localhost:8080/meta/redirects.json",
                "",
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                900,
                false,
                TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now()),
                TimeUtils.localDateTimeToEpochSecond(LocalDateTime.now())
        );
    }

    private User defaultUser() {
        var user = new User(
                "rexijie",
                encoder.encode("password"),
                "gisBae@rexijie.dev",
                Set.of(new Authority("ADMIN"),
                        new Authority(AuthorityEnum.CAN_CREATE),
                        new Authority(AuthorityEnum.CAN_DELETE),
                        new Authority(AuthorityEnum.CAN_MODIFY),
                        new Authority(AuthorityEnum.CAN_VIEW)
                )
        );
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setCredentialsNonExpired(true);
        user.setAccountNonLocked(true);
        return user;
    }

}

