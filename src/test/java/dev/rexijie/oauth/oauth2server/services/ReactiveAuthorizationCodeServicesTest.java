package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import dev.rexijie.oauth.oauth2server.token.granter.TokenGranterTest;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class ReactiveAuthorizationCodeServicesTest extends TokenGranterTest {

    ReactiveAuthorizationCodeServices authorizationCodeServices;

    @Override
    public void setUp() {
        authorizationCodeServices = new DefaultReactiveAuthorizationCodeServices(
                clientService,
                tokenService,
                codeRepository,
                new RandomStringSecretGenerator(),
                tokenServices
        );

    }

    @Test
    void createAuthorizationCode() {
        var client = testClient();
        var user = testUser();
        when(codeRepository.save(any(AuthorizationCodeWrapper.class)))
                .then(returnsMonoAtArg());

        when(clientRepository.findByClientId(client.clientId()))
                .thenReturn(Mono.just(client));

        when(userRepository.findByUsername(user.getUsername()))
                .thenReturn(Mono.just(user));

        when(tokenEnhancer.enhance(any(), any()))
                .then(returnsMonoAtArg());

        var clientAuth = clientAuthentication();
        Mono<AuthorizationCodeWrapper> authorizationCode = authorizationCodeServices.createAuthorizationCode(clientAuth);

        StepVerifier.create(authorizationCode)
                .consumeNextWith(authorizationCodeWrapper -> {
                    assertThat(authorizationCodeWrapper.getCode())
                            .isNotEmpty();
                    assertThat(authorizationCodeWrapper.getAuthentication())
                            .isNotNull();
                })
                .verifyComplete();
    }

    @Test
    void consumeAuthorizationCode() {
        when(tokenEnhancer.readAuthentication(any(), any()))
                .thenReturn(Mono.just(clientAuthentication()));

        when(tokenEnhancer.isEnhanced(any()))
                .thenReturn(Mono.just(true));

        when(codeRepository.findByCode(any(String.class)))
                .thenReturn(Mono.just(authenticationWrapper()));

        Mono<OAuth2Authentication> created_code = authorizationCodeServices.consumeAuthorizationCode("created_code", clientAuthentication());
        StepVerifier.create(created_code)
                .consumeNextWith(authentication -> {
                    assertThat(authentication.getUserPrincipal())
                            .isNotNull().isEqualTo(testUser().getUsername());
                    assertThat(authentication.getPrincipal())
                            .isNotNull()
                            .isEqualTo(testClient().clientId());
                    assertThat(authentication.getStoredRequest())
                            .isEqualTo(authorizationRequest());
                })
                .verifyComplete();

    }

    @Override
    protected AuthorizationRequest authorizationRequest() {
        return new AuthorizationRequest(
                "authorization_code",
                "code",
                "test-client",
                "http://localhost:8080/oauth/code",
                "read write",
                "nonce",
                "random_state"
        );
    }
}