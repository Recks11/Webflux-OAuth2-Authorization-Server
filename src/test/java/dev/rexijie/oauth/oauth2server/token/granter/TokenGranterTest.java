package dev.rexijie.oauth.oauth2server.token.granter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.auth.EncryptedCodeAuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveClientAuthenticationManager;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveUserAuthenticationManager;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import dev.rexijie.oauth.oauth2server.generators.SecretGenerator;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveAuthorizationCodeServices;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientDetailsService;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientService;
import dev.rexijie.oauth.oauth2server.services.token.DefaultTokenServices;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.services.user.DefaultReactiveUserDetailsService;
import dev.rexijie.oauth.oauth2server.services.user.DefaultUserService;
import dev.rexijie.oauth.oauth2server.token.NimbusJOSETokenProcessor;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.Signer;
import dev.rexijie.oauth.oauth2server.token.enhancer.TokenEnhancer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.CLIENT_AUTHENTICATION_METHOD;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.Authentication.createClientAuthentication;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultClient;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.getDefaultUser;
import static dev.rexijie.oauth.oauth2server.token.claims.ClaimNames.Custom.AUTHORIZATION_REQUEST;
import static dev.rexijie.oauth.oauth2server.token.claims.ClaimNames.Custom.SCOPES;

@ExtendWith(MockitoExtension.class)
public abstract class TokenGranterTest {

    @Mock
    protected UserRepository userRepository;
    @Mock
    protected ClientRepository clientRepository;
    @Mock
    protected AuthorizationCodeRepository codeRepository;
    @Mock
    protected TokenEnhancer tokenEnhancer;
    protected ClientService clientService;
    protected TokenService tokenService;
    protected TokenServices tokenServices;
    protected ObjectMapper objectMapper;
    protected PasswordEncoder encoder;
    protected ReactiveUserAuthenticationManager reactiveUserAuthenticationManager;
    protected ReactiveClientAuthenticationManager reactiveClientAuthenticationManager;
    protected SecretGenerator secretGenerator = new RandomStringSecretGenerator();

    @BeforeEach
    void initializeClient() {
        objectMapper = ServiceMocks.ConfigBeans.testObjectMapper();
        encoder = ServiceMocks.ConfigBeans.testPasswordEncoder();
        tokenService = ServiceMocks.ConfigBeans.testTokenService();

        clientService = new DefaultClientService(
                clientRepository, ServiceMocks.ConfigBeans.credentialsGenerator(), encoder);

        tokenServices = new DefaultTokenServices(
                clientService,
                new DefaultUserService(userRepository, encoder, objectMapper),
                tokenEnhancer,
                tokenService);

        reactiveUserAuthenticationManager = new ReactiveUserAuthenticationManager(
                new DefaultReactiveUserDetailsService(userRepository)
        );
        reactiveUserAuthenticationManager.setPasswordEncoder(encoder);

        reactiveClientAuthenticationManager = new ReactiveClientAuthenticationManager(
                new DefaultClientDetailsService(clientRepository, encoder)
        );

        setUp();
    }

    protected Client testClient() {
        return getDefaultClient(encoder.encode("secret"));
    }

    protected User testUser() {
        return getDefaultUser(encoder.encode("password"));
    }

    protected Mono<AuthorizationCodeWrapper> authenticationWrapper() {
        var add = new DefaultReactiveAuthorizationCodeServices(clientService, tokenService, codeRepository, secretGenerator,
                tokenServices);
        try {
            return getMockToken()
                    .map(token -> {
                        var additionalInfo = add.createAdditionalInformation(token);
                        Token token1 = tokenService.allocateToken(additionalInfo);
                        return new EncryptedCodeAuthorizationCodeWrapper("authentication_code",
                                token1.getKey().getBytes(StandardCharsets.UTF_8));
                    });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected Mono<String> getMockToken() {
        var rsaKey = KeyGen.generateRSAJWK();
        var ecKey = KeyGen.generateECKey();
        Signer jwtSigner = new NimbusJOSETokenProcessor(
                null,
                new ImmutableJWKSet<>(new JWKSet(List.of(rsaKey, ecKey)))
        );

        return jwtSigner.sign(createApprovalToken());
    }

    protected OAuth2Authentication clientAuthentication() {
        var clientAuth = createClientAuthentication(ModelMocks.getDefaultClient(encoder.encode("secret")));
        clientAuth.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                authorizationRequest(),
                ModelMocks.Authentication.mockUserAuthentication(ModelMocks.testUser())
        ));

        clientAuth.getStoredRequest().setAttribute(CLIENT_AUTHENTICATION_METHOD,
                ((ClientDTO) clientAuth.getDetails()).getTokenEndpointAuthenticationMethod());
        return clientAuth;
    }

    private SignedJWT createApprovalToken() {
        var authentication = clientAuthentication();
        var payload = new JWTClaimsSet.Builder()
                .jwtID(secretGenerator.generate(24))
                .issuer(ServiceMocks.ConfigBeans.mockProperties().openId().issuer())
                .subject(authentication.getUserPrincipal().toString())
                .audience(authentication.getPrincipal().toString())
                .notBeforeTime(Date.from(Instant.ofEpochSecond(authentication.getAuthenticationTime())))
                .claim(AUTHORIZATION_REQUEST,
                        new ObjectMapper().convertValue(authentication.getAuthorizationRequest().storedRequest(),
                                new TypeReference<Map<String, Object>>() {
                                }))
                .claim(SCOPES, authentication.getAuthorizationRequest().storedRequest().getScope())
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
                .build();

        return new SignedJWT(
                // TODO make dynamic
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                payload
        );
    }

    protected abstract void setUp();

    protected abstract AuthorizationRequest authorizationRequest();
}
