package dev.rexijie.oauth.oauth2server.token.enhancer;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.security.keys.InMemoryRSAKeyPairStore;
import dev.rexijie.oauth.oauth2server.token.NimbusdsJoseTokenSigner;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.Signer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;


class JwtGeneratingTokenEnhancerTest {

    private TokenEnhancer enhancer;
    private TokenService tokenService;
    private final String jwtPattern = "(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)";

    @BeforeEach
    void setUp() {
        OAuth2Properties properties = ServiceMocks.ConfigBeans.mockProperties();
        tokenService = ServiceMocks.ConfigBeans.testTokenService();
        Signer jwtSigner = new NimbusdsJoseTokenSigner(new InMemoryRSAKeyPairStore(KeyGen.generateRSAKeys()));
        enhancer = new JwtGeneratingTokenEnhancer(properties, tokenService, jwtSigner);
    }

    @Test
    void enhance() {
        String tokenValue = tokenService.allocateToken("username=rex").getKey();
        var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                tokenValue,
                Instant.now(),
                Instant.now().plusSeconds(3600));

        Mono<OAuth2Token> enhance = enhancer.enhance(
                accessToken,
                createAuthentication());

        StepVerifier.create(enhance)
                .consumeNextWith(auth2Token -> assertThat(auth2Token).isNotNull()
                        .extracting(OAuth2Token::getTokenValue)
                        .asString().isNotEmpty()
                        .containsPattern(jwtPattern))
                .verifyComplete();
    }

    private OAuth2Authentication createAuthentication() {
        var clientAuth = ModelMocks.Authentication.createClientAuthentication(ModelMocks.testClient());
        clientAuth.setAuthorizationRequest(new OAuth2AuthorizationRequest(
                new AuthorizationRequest(
                        "password",
                        null,
                        "test-client",
                        "http://localhost:8080/oauth/code",
                        "read write",
                        "nonce",
                        "random_state"
                ),
                ModelMocks.Authentication.mockUserAuthentication(ModelMocks.getDefaultUser("pwd"))
        ));
        return clientAuth;
    }
}