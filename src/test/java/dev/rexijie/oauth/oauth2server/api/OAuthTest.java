package dev.rexijie.oauth.oauth2server.api;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.MultiValueMapAdapter;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import reactor.core.publisher.Mono;

import java.util.Base64;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultClient;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultUser;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.when;


// TODO (convert to integration test)
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
public abstract class OAuthTest {


    @Autowired private WebTestClient webTestClient;
    @Autowired private PasswordEncoder passwordEncoder;

    @MockBean protected UserRepository userRepository;
    @MockBean protected ClientRepository clientRepository;
    @MockBean protected AuthorizationCodeRepository codeRepository;

    protected static String APPROVAL_ENDPOINT = "/oauth/approve";
    protected static String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    protected static String TOKEN_ENDPOINT = "/oauth/token";
    protected static String LOGIN_ENDPOINT = "/login";

    @BeforeEach
    void initializeClient() {
        var client = testClient();
        var user = testUser();
        when(clientRepository.findByClientId(client.clientId()))
                .thenReturn(Mono.just(client));

        when(userRepository.findByUsername(user.getUsername()))
                .thenReturn(Mono.just(user));

        when(clientRepository.save(any(Client.class)))
                .then(returnsMonoAtArg());

        when(userRepository.save(any(User.class)))
                .then(returnsMonoAtArg());

        when(clientRepository.deleteAll()).thenReturn(Mono.empty());
        when(userRepository.deleteAll()).thenReturn(Mono.empty());

        setUp();
    }

    @AfterEach
    void cleanSlate() {
        clearInvocations(userRepository, clientRepository, codeRepository);
    }

    public WebTestClient apiClient() {
        return webTestClient;
    }

    public WebTestClient authClient() {
        return webTestClient.mutate()
                .defaultHeader("Authorization", "Basic %s".formatted(getBasicCredentials()))
                .build();
    }

    public String getBasicCredentials() {
        return Base64.getEncoder().encodeToString(
                "test-client:secret".getBytes()
        );
    }

    protected UriBuilder getUriBuilder() {
        var client = testClient();
        return new DefaultUriBuilderFactory().builder()
                .path(AUTHORIZATION_ENDPOINT)
                .queryParam("grant_type", "authorization_code")
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", client.registeredRedirectUris().toArray()[0])
                .queryParam("client_id", client.clientId())
                .queryParam("scopes", "read write")
                .queryParam("state", "random_state")
                .queryParam("nonce", "random_nonce_string");

    }

    private Client testClient() {
        return getDefaultClient(passwordEncoder.encode("secret"));
    }

    private User testUser() {
        return getDefaultUser(passwordEncoder.encode("password"));
    }

    public abstract void setUp();
}
