package dev.rexijie.oauth.oauth2server.token.granter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveClientAuthenticationManager;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveUserAuthenticationManager;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientDetailsService;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientService;
import dev.rexijie.oauth.oauth2server.services.token.DefaultTokenServices;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.services.user.DefaultReactiveUserDetailsService;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import dev.rexijie.oauth.oauth2server.token.enhancer.TokenEnhancer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultClient;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultUser;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public abstract class TokenGranterTest {

    @Mock protected UserRepository userRepository;
    @Mock protected ClientRepository clientRepository;
    @Mock protected AuthorizationCodeRepository codeRepository;
    @Mock protected TokenEnhancer tokenEnhancer;
    protected ClientService clientService;
    protected TokenService tokenService;
    protected TokenServices tokenServices;
    protected ObjectMapper objectMapper;
    protected PasswordEncoder encoder;
    protected ReactiveUserAuthenticationManager reactiveUserAuthenticationManager;
    protected ReactiveClientAuthenticationManager reactiveClientAuthenticationManager;

    @BeforeEach
    void initializeClient() {
        objectMapper = ServiceMocks.ConfigBeans.testObjectMapper();
        encoder = ServiceMocks.ConfigBeans.testPasswordEncoder();
        tokenService = ServiceMocks.ConfigBeans.testTokenService();

        clientService = new DefaultClientService(
                clientRepository, ServiceMocks.ConfigBeans.credentialsGenerator(),  encoder);
        tokenServices = new DefaultTokenServices(
                clientService,
                tokenEnhancer,
                tokenService);

        reactiveUserAuthenticationManager = new ReactiveUserAuthenticationManager(
                new DefaultReactiveUserDetailsService(userRepository)
        );
        reactiveUserAuthenticationManager.setPasswordEncoder(encoder);

        reactiveClientAuthenticationManager = new ReactiveClientAuthenticationManager(
                new DefaultClientDetailsService(clientRepository, encoder)
        );

        when(tokenEnhancer.enhance(any(), any(Authentication.class)))
                .then(returnsMonoAtArg());
        setUp();
    }

    protected Client testClient() {
        return getDefaultClient(encoder.encode("secret"));
    }

    protected User testUser() {
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
