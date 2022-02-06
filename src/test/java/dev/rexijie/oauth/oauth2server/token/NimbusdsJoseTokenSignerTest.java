package dev.rexijie.oauth.oauth2server.token;

import dev.rexijie.oauth.oauth2server.generators.KeyGen;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.security.keys.InMemoryRSAKeyPairStore;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static dev.rexijie.oauth.oauth2server.mocks.TokenMocks.getPlainToken;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class NimbusdsJoseTokenSignerTest {

    private Signer signer;

    @BeforeEach
    void setup() {
        KeyPairStore<RSAPrivateKey, RSAPublicKey> kps = new InMemoryRSAKeyPairStore(KeyGen.generateKeys());
        signer = new NimbusdsJoseTokenSigner(kps, ServiceMocks.ConfigBeans.mockProperties());
    }

    @Test
    void canSignTokens() {
        var token = getPlainToken();
        Mono<String> sign = signer.sign(token);
        StepVerifier.create(sign)
                .consumeNextWith(tk -> assertThat(tk).isNotNull().containsPattern("(^[\\w-]*\\.[\\w-]*\\.[\\w-]*$)"))
                .verifyComplete();
    }

    @Test
    void canVerifySignedTokens() {
        var token = getPlainToken();
        Mono<Boolean> verify = signer.sign(token)
                .flatMap(signer::verify);
        StepVerifier.create(verify)
                .assertNext(Assertions::assertTrue)
                .verifyComplete();
    }


    @Test
    void whenVerifyTokensWithBadKeys_thenError() {
        var token = getPlainToken();
        Mono<Boolean> verify = signer.sign(token)
                .flatMap(s -> {
                    setup();
                    return signer.verify(s);
                });

        StepVerifier.create(verify)
                .assertNext(Assertions::assertFalse)
                .verifyComplete();
    }

    @Test
    void whenVerifyTokensWithBadToken_thenError() {
        var token = getPlainToken();
        Mono<Boolean> verify = signer.sign(token)
                .flatMap(s -> signer.verify(s.substring(2, s.length() - 5)));

        StepVerifier.create(verify)
                .expectError(JwtException.class)
                .verify();
    }
}