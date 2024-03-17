package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static dev.rexijie.oauth.oauth2server.mocks.TokenMocks.getToken;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class NimbusJOSETokenProcessorTest {

    private NimbusJOSETokenProcessor processor;

    @BeforeEach
    void setUp() {
        var rsaKey = KeyGen.generateRSAJWK();
        var ecKey = KeyGen.generateECKey();
        var privateKeySource = new JWKSet(List.of(rsaKey, ecKey));
        try {
            processor = new NimbusJOSETokenProcessor(
                    JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(
                            new ImmutableJWKSet<>(privateKeySource.toPublicJWKSet())
                    ),
                    new ImmutableJWKSet<>(privateKeySource)
            );
        } catch (Exception ex) {
            System.out.println("ERROR INSTANTIATING CLASSES");
        }

    }

    @Test
    void sign() {
        var token = getToken();
        Mono<String> sign = processor.sign(token);
        StepVerifier.create(sign)
                .consumeNextWith(tk -> assertThat(tk).isNotNull().containsPattern("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)"))
                .verifyComplete();
    }

    @Test
    void canSignAndVerifyToken() {
        var token = getToken();
        Mono<Boolean> verify = processor.sign(token)
                .flatMap(processor::verify);
        StepVerifier.create(verify)
                .assertNext(Assertions::assertTrue)
                .verifyComplete();
    }

    //    @Test
    void deserialize() {
    }

    @Test
    void whenVerifyTokensWithBadKeys_thenError() {
        var token = getToken();
        Mono<Boolean> verify = processor.sign(token)
                .flatMap(s -> {
                    setUp();
                    return processor.verify(s);
                });

        StepVerifier.create(verify)
                .assertNext(Assertions::assertFalse)
                .verifyComplete();
    }

    //    @Test
    void verifyClaims() {
    }

    @Test
    void whenVerifyTokensWithBadToken_thenError() {
        var token = getToken();
        Mono<Boolean> verify = processor.sign(token)
                .flatMap(s -> processor.verify(s.substring(2, s.length() - 5)));

        StepVerifier.create(verify)
                .assertNext(Assertions::assertFalse)
                .verifyComplete();
    }
}