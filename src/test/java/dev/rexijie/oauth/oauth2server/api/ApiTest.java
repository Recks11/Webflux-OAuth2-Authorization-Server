package dev.rexijie.oauth.oauth2server.api;

import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.AdditionalAnswers;
import org.mockito.internal.stubbing.answers.ReturnsArgumentAt;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.when;


@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
public abstract class ApiTest {

    @Autowired WebTestClient webTestClient;
    @MockBean private UserRepository userRepository;
    @MockBean private ClientRepository clientRepository;
    @Autowired OAuth2Properties oAuth2Properties;
    @Autowired PasswordEncoder passwordEncoder;

    @BeforeEach
    void initializeClient() {
        when(clientRepository.findByClientId(any(String.class)))
                .thenReturn(Mono.just(getDefaultClient()));

        when(userRepository.findByUsername(any(String.class)))
                .thenReturn(Mono.just(getDefaultUser()));

        when(clientRepository.save(any(Client.class)))
                .then(returnsMonoAtArg());

        when(userRepository.save(any(User.class)))
                .then(returnsMonoAtArg());

        when(clientRepository.deleteAll()).thenReturn(Mono.empty());
        when(userRepository.deleteAll()).thenReturn(Mono.empty());
    }

    @AfterEach
    void cleanSlate() {
        clearInvocations(userRepository, clientRepository);
    }

    public WebTestClient apiClient() {
        return webTestClient;
    }

    public WebTestClient authClient() {
        return webTestClient.mutate()
                .defaultHeader("Authorization", "basic %s".formatted(getBasicCredentials()))
                .build();
    }

    public String getBasicCredentials() {
        return Base64.getEncoder().encodeToString(
                "test-client:secret".getBytes()
        );
    }

    public static Answer<?> returnsMonoAtArg() {
        return invocation -> {
            ReturnsArgumentAt returnsArgumentAt = new ReturnsArgumentAt(0);
            returnsArgumentAt.validateFor(invocation);
            Object answer = returnsArgumentAt.answer(invocation);
            return Mono.just(answer);
        };
    }

    protected Client getDefaultClient() {
        return ModelMocks.testClient(passwordEncoder.encode("secret"));
    }

    protected User getDefaultUser() {
        User testUser = ModelMocks.testUser(passwordEncoder.encode("password"));
        testUser.setAccountNonLocked(true);
        testUser.setEnabled(true);
        testUser.setAccountNonExpired(true);
        testUser.setCredentialsNonExpired(true);
        return testUser;
    }
}
