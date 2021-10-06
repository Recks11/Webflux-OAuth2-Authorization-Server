package dev.rexijie.oauth.oauth2server.token.granter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationSerializationWrapper;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.SecureRandomFactoryBean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;

import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultClient;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultUser;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public abstract class TokenGranterTest {

    @MockBean
    protected UserRepository userRepository;
    @MockBean
    protected ClientRepository clientRepository;
    @MockBean
    protected AuthorizationCodeRepository codeRepository;
    protected KeyBasedPersistenceTokenService tokenService;
    protected ObjectMapper objectMapper;
    protected PasswordEncoder encoder;

    @BeforeEach
    void initializeClient() {
        objectMapper = new ObjectMapper();
        encoder = new BCryptPasswordEncoder();
        tokenService = new KeyBasedPersistenceTokenService();
        tokenService.setServerSecret("stoke-serbert");
        tokenService.setServerInteger(42001);
        tokenService.setPseudoRandomNumberBytes(64);
        try {
            tokenService.setSecureRandom(new SecureRandomFactoryBean().getObject());
        } catch (Exception exception) {
            //
        }

        when(clientRepository.findByClientId(testClient().clientId()))
                .thenReturn(Mono.just(testClient()));

        when(userRepository.findByUsername(testUser().getUsername()))
                .thenReturn(Mono.just(testUser()));

        when(clientRepository.save(any(Client.class)))
                .then(returnsMonoAtArg());

        when(userRepository.save(any(User.class)))
                .then(returnsMonoAtArg());

        when(codeRepository.save(any(AuthenticationSerializationWrapper.class)))
                .then(returnsMonoAtArg());

        when(codeRepository.findByCode(any(String.class)))
                .thenReturn(Mono.just(getAuthenticationWrapper()));

        when(clientRepository.deleteAll()).thenReturn(Mono.empty());
        when(userRepository.deleteAll()).thenReturn(Mono.empty());

        setUp();
    }

    private AuthenticationSerializationWrapper getAuthenticationWrapper() {
        var add = new DefaultReactiveAuthorizationCodeServices(null, null, null, null,
                new RandomStringSecretGenerator());
        try {
            return new AuthenticationSerializationWrapper("authentication_code",
                    tokenService.allocateToken(add.createAdditionalInformation(getApprovalToken())).getKey(),
                    objectMapper.writeValueAsBytes(getApprovalToken()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Client testClient() {
        return getDefaultClient(encoder.encode("secret"));
    }

    private User testUser() {
        return getDefaultUser(encoder.encode("password"));
    }

    protected OAuth2ApprovalAuthorizationToken getApprovalToken() {
        var client = testClient();
        var token = new OAuth2ApprovalAuthorizationToken(
                "rexijie",
                "[YOU THOUGHT]",
                new AuthorizationRequest(
                        "authorization_code",
                        "code",
                        client.clientId(),
                        client.registeredRedirectUris().toArray(new String[]{})[0],
                        "read write",
                        "random_nonce_string",
                        "random_state"
                )
        );
        token.setApprovalTokenId("eyJhdXRob3JpdGIlcyl6W10sImRidGFp");
        token.setDetails(ClientDTO.ClientMapper.toDto(client));
        token.setAuthenticated(true);
        token.approve("read");
        token.approve("write");
        return token;
    }

    abstract void setUp();
}
