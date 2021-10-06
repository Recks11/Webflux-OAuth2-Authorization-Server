package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveUserAuthenticationManager;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.mocks.ServiceMocks;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.services.user.DefaultReactiveUserDetailsService;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
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

class ResourceOwnerPasswordCredentialsTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;

    @Override
    void setUp() {
        tokenGranter = new ResourceOwnerPasswordCredentialsTokenGranter(
                tokenServices,
                reactiveUserAuthenticationManager
        );

        when(userRepository.findByUsername(testUser().getUsername()))
                .thenReturn(Mono.just(testUser()));
    }

    @Test
    void canGrantResourceOwnerClientCredentialsToken() {
        String password = "password";

        AuthorizationRequest ar = new AuthorizationRequest(
                "password",
                null,
                "test-client",
                "http://localhost:8080/oauth/code",
                "read write",
                "nonce",
                "random_state"
        );
        ar.getAttributes().put(USERNAME_ATTRIBUTE, "rexijie");
        ar.getAttributes().put(PASSWORD_ATTRIBUTE, password);

        var clientAuth = createClientAuthentication(ModelMocks.getDefaultClient(encoder.encode("secret")));

        Mono<OAuth2Token> oAuth2TokenMono = tokenGranter.grantToken(clientAuth, ar);

        StepVerifier.create(oAuth2TokenMono)
                .consumeNextWith(auth2Token -> {
                    assertThat(auth2Token).isNotNull();
                    verify(tokenEnhancer, times(1))
                            .enhance(any(OAuth2AccessToken.class), any(Authentication.class));
                }).verifyComplete();
    }
}