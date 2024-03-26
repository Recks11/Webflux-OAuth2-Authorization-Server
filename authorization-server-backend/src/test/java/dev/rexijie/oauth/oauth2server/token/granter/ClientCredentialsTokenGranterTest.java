package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationStage;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.token.AuthorizationTokenResponse;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.Authentication.createClientAuthentication;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ClientCredentialsTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;

    @Test
    void grantToken() {

        Mono<AuthorizationTokenResponse> oAuth2TokenMono = tokenGranter.grantToken(clientAuthentication(),
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
        tokenGranter = new ClientCredentialsTokenGranter(
                tokenServices,
                reactiveClientAuthenticationManager
        );

        when(tokenEnhancer.enhance(any(), any(Authentication.class)))
                .then(returnsMonoAtArg());
    }

    @Override
    protected AuthorizationRequest authorizationRequest() {
        return AuthorizationRequest.from(Map.of(
                "grant_type", "client_credentials",
                "scope", "read write")
        );
    }

    @Override
    protected OAuth2Authentication clientAuthentication() {
        var auth = createClientAuthentication(ModelMocks.getDefaultClient(
                encoder.encode("secret")
        ));
        auth.setAuthenticationStage(AuthenticationStage.COMPLETE);
        auth.setAuthorizationRequest(
                new OAuth2AuthorizationRequest(
                        authorizationRequest(),
                        null
                )
        );
        return auth;
    }
}