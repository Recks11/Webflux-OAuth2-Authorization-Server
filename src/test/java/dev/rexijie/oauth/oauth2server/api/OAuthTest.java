package dev.rexijie.oauth.oauth2server.api;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.mongo.MongoReactiveDataAutoConfiguration;
import org.springframework.boot.autoconfigure.data.mongo.MongoReactiveRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoReactiveAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
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
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;
import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.NONCE;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

// TODO (convert to integration test)
@SpringBootTest
@EnableAutoConfiguration(exclude = {
        MongoReactiveAutoConfiguration.class,
        MongoReactiveDataAutoConfiguration.class,
        MongoReactiveRepositoriesAutoConfiguration.class
})
@ActiveProfiles("test")
public abstract class OAuthTest {


    @Autowired private ApplicationContext context;
    private WebTestClient webClient;
    private WebTestClient authWebClient;
    private PasswordEncoder passwordEncoder;

    @MockBean protected UserRepository userRepository;
    @MockBean protected ClientRepository clientRepository;
    @MockBean protected AuthorizationCodeRepository codeRepository;

    protected static String APPROVAL_ENDPOINT = "/oauth/approve";
    protected static String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    protected static String TOKEN_ENDPOINT = "/oauth/token";
    protected static String LOGIN_ENDPOINT = "/login";

    @BeforeEach
    void initializeClient() {
        this.authWebClient = WebTestClient
                .bindToApplicationContext(context)
                .apply(springSecurity())
                .configureClient()
                .filter(basicAuthentication("test-client", "secret"))
                .build();

        this.webClient = WebTestClient.bindToApplicationContext(context)
                .configureClient()
                .build();

        passwordEncoder = new BCryptPasswordEncoder();
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
        return webClient;
    }

    public WebTestClient authClient() {
        return this.authWebClient;
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
                .queryParam(GRANT_TYPE, "authorization_code")
                .queryParam(RESPONSE_TYPE, "code")
                .queryParam(REDIRECT_URI, client.registeredRedirectUris().toArray()[0])
                .queryParam(CLIENT_ID, client.clientId())
                .queryParam(SCOPE, "read write")
                .queryParam(STATE, "random_state")
                .queryParam(NONCE, "random_nonce_string");

    }

    private Client testClient() {
        return getDefaultClient(passwordEncoder.encode("secret"));
    }

    private User testUser() {
        return getDefaultUser(passwordEncoder.encode("password"));
    }

    public abstract void setUp();
}
