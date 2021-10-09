package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.Authentication.createClientAuthentication;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ImplicitTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;

//    @Test
    void grantToken() {
        Mono<OAuth2Token> oAuth2TokenMono = tokenGranter.grantToken(
                clientAuthentication(),
                authorizationRequest());

        StepVerifier.create(oAuth2TokenMono)
                .consumeNextWith(auth2Token -> {
                    assertThat(auth2Token).isNotNull();
                    verify(tokenEnhancer, times(1))
                            .enhance(any(OAuth2AccessToken.class), any(Authentication.class));
                }).verifyComplete();
    }

    @Override
    protected void setUp() {
        tokenGranter = new ImplicitTokenGranter(
                tokenServices,
                reactiveClientAuthenticationManager
        );

        when(clientRepository.findByClientId(testClient().clientId()))
                .thenReturn(Mono.just(testClient()));

        when(userRepository.findByUsername(testUser().getUsername()))
                .thenReturn(Mono.just(testUser()));

        when(tokenEnhancer.enhance(any(), any(Authentication.class)))
                .then(returnsMonoAtArg());
    }

    @Override
    protected AuthorizationRequest authorizationRequest() {
        var ar = new AuthorizationRequest(
                "implicit",
                "token",
                "test-client",
                "http://localhost:8080/oauth/code",
                "read write",
                "nonce",
                "random_state"
        );
        ar.getAttributes().put(USERNAME_ATTRIBUTE, "rexijie");
        ar.getAttributes().put(PASSWORD_ATTRIBUTE, "password");

        return ar;
    }
}