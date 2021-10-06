package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationSerializationWrapper;
import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveAuthorizationCodeServices;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.Authentication.createClientAuthentication;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthorizationCodeTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;

    @Test
    void grantToken() {
        String password = "password";

        AuthorizationRequest ar = new AuthorizationRequest(
                "authorization_code",
                "code",
                "test-client",
                "http://localhost:8080/oauth/code",
                "read write",
                "nonce",
                "random_state"
        );
        ar.getAttributes().put("code", "generated_code");
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

    @Override
    void setUp() {
        tokenGranter = new AuthorizationCodeTokenGranter(
                tokenServices,
                new DefaultReactiveAuthorizationCodeServices(
                        clientService,
                        tokenService,
                        codeRepository,
                        objectMapper,
                        new RandomStringSecretGenerator()
                )
        );

        when(codeRepository.findByCode(any(String.class)))
                .thenReturn(Mono.just(getAuthenticationWrapper()));
    }

    private AuthenticationSerializationWrapper getAuthenticationWrapper() {
        var add = new DefaultReactiveAuthorizationCodeServices(null, null, null, null,
                new RandomStringSecretGenerator());
        try {
            return new AuthenticationSerializationWrapper("authentication_code",
                    tokenService.allocateToken(add.createAdditionalInformation(getApprovalToken())).getKey(),
                    objectMapper.writeValueAsBytes(getApprovalToken()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}