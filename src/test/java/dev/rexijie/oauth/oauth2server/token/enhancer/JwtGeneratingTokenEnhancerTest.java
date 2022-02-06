package dev.rexijie.oauth.oauth2server.token.enhancer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.token.NimbusJOSETokenProcessor;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;


class JwtGeneratingTokenEnhancerTest {

    private TokenEnhancer enhancer;
    private TokenService tokenService;
    private final String jwtPattern = "(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)";

    @BeforeEach
    void setUp() throws JOSEException {
        tokenService = ServiceMocks.ConfigBeans.testTokenService();
        var privateKeySource = new JWKSet(List.of(KeyGen.generateRSAJWK(), KeyGen.generateECKey()));
        JWSKeySelector<SecurityContext> keySelector = JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(
                new ImmutableJWKSet<>(privateKeySource.toPublicJWKSet())
        );
        var signer = new NimbusJOSETokenProcessor(
                keySelector,
                new ImmutableJWKSet<>(privateKeySource)
        );

//        Signer jwtSigner = new NimbusdsJoseTokenSigner(new InMemoryRSAKeyPairStore(KeyGen.generateRSAKeys()), properties);
        enhancer = new JwtGeneratingTokenEnhancer(ServiceMocks.ConfigBeans.mockProperties(), tokenService, signer);
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
        clientAuth.setAuthenticationStage(AuthenticationStage.COMPLETE);
        return clientAuth;
    }
}