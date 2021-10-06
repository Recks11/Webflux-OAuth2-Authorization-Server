package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.Authentication.createClientAuthentication;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

class ClientCredentialsTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;

    @Test
    void grantToken() {
        AuthorizationRequest ar = AuthorizationRequest.from(Map.of(
                "grant_type", "client_credentials",
                "scope", "read write")
        );

        var clientAuth = createClientAuthentication(ModelMocks.getDefaultClient(encoder.encode("secret")));

        Mono<OAuth2Token> oAuth2TokenMono = tokenGranter.grantToken(clientAuth, ar);

        StepVerifier.create(oAuth2TokenMono)
                .consumeNextWith(auth2Token -> {
                    assertThat(auth2Token).isNotNull();
                }).verifyComplete();
    }

    @Override
    void setUp() {
        tokenGranter = new ClientCredentialsTokenGranter(
                tokenServices,
                reactiveClientAuthenticationManager
        );

//        when(clientRepository.findByClientId(testClient().clientId()))
//                .thenReturn(Mono.just(testClient()));
    }
}