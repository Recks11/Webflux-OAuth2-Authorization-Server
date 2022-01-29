package dev.rexijie.oauth.oauth2server.token.granter;

import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.services.ReactiveAuthorizationCodeServices;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.utils.TestUtils.returnsMonoAtArg;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthorizationCodeTokenGranterTest extends TokenGranterTest {

    TokenGranter tokenGranter;
    @Mock ReactiveAuthorizationCodeServices authorizationCodeServices;

    @Override
    protected void setUp() {
        tokenGranter = new AuthorizationCodeTokenGranter(
                tokenServices,
                authorizationCodeServices
        );

        when(clientRepository.findByClientId(testClient().clientId()))
                .thenReturn(Mono.just(testClient()));

        when(userRepository.findByUsername(testUser().getUsername()))
                .thenReturn(Mono.just(testUser()));

        when(tokenEnhancer.enhance(any(), any(Authentication.class)))
                .then(returnsMonoAtArg());
    }

    @Test
    void grantToken() {
        String code = clientAuthentication().getStoredRequest().getAttribute("code");
        when(authorizationCodeServices.consumeAuthorizationCode(eq(code), any()))
                .then(returnsMonoAtArg(1));
        Mono<OAuth2Token> oAuth2TokenMono = tokenGranter.grantToken(clientAuthentication(), authorizationRequest());

        StepVerifier.create(oAuth2TokenMono)
                .consumeNextWith(auth2Token -> {
                    assertThat(auth2Token).isNotNull();
                    verify(tokenEnhancer, times(1))
                            .enhance(any(OAuth2AccessToken.class), any(Authentication.class));
                }).verifyComplete();
    }

    @Test
    void givenInvalidRequest_whenGenerateToken_thenError() {
        String code = clientAuthentication().getStoredRequest().getAttribute("code");
        when(authorizationCodeServices.consumeAuthorizationCode(any(), any()))
                .then(returnsMonoAtArg(1));

        var ar = new AuthorizationRequest(
                        "invalid_grant",
                        "code",
                        "test-client",
                        "http://localhost:8080/oauth/code",
                        "read what?",
                        "noNonce",
                        "state_file");

        ar.setAttribute("code", "invalid_code");
        ar.setAttribute(USERNAME_ATTRIBUTE, "rexijie");
        ar.setAttribute(PASSWORD_ATTRIBUTE, "password");
        Mono<OAuth2Token> token = tokenGranter.grantToken(clientAuthentication(), ar);

        StepVerifier.create(token)
                .expectError(OAuthError.class)
                .verify();
    }

    protected AuthorizationRequest authorizationRequest() {
        AuthorizationRequest ar = new AuthorizationRequest(
                "authorization_code",
                "code",
                "test-client",
                "http://localhost:8080/oauth/code",
                "read write",
                "nonce",
                "random_state"
        );
        ar.setAttribute("code", "valid_code");
        ar.setAttribute(USERNAME_ATTRIBUTE, "rexijie");
        ar.setAttribute(PASSWORD_ATTRIBUTE, "password");
        return ar;
    }
}