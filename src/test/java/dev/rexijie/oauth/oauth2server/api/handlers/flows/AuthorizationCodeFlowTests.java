package dev.rexijie.oauth.oauth2server.api.handlers.flows;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import dev.rexijie.oauth.oauth2server.mocks.ModelMocks;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.PASSWORD_ATTRIBUTE;
import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.USERNAME_ATTRIBUTE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthorizationCodeFlowTests extends OAuthTest {
    private static final Map<String, ResponseCookie> responseCookieState = new HashMap<>();

    @Test
    @Order(1)
    void when_authorize_then_redirect_to_login() {

        URI authorizationUri = getUriBuilder().build();
        //initiate authorization
        FluxExchangeResult<Object> initialResponse = authClient()
                .get()
                .uri(authorizationUri)
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().location(getUriBuilder().replacePath(LOGIN_ENDPOINT).build().toString())
                .expectCookie().exists("SESSION")
                .returnResult(Object.class);

        ResponseCookie session = initialResponse.getResponseCookies().getFirst("SESSION");

        responseCookieState.put("COOKIE", session);
    }

    @Test
    @Order(2)
    void when_login_expect_redirect_to_approval() {

        URI authorizationUri = getUriBuilder().build();
        var session = responseCookieState.get("COOKIE");
        // provide credentials
        FluxExchangeResult<Object> loginResult = authClient()
                .post()
                .uri(authorizationUri)
                .cookie(session.getName(), session.getValue())
                .body(BodyInserters
                        .fromFormData(USERNAME_ATTRIBUTE, "rexijie")
                        .with(PASSWORD_ATTRIBUTE, "password")
                )
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().location(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .expectCookie().exists("SESSION")
                .returnResult(Object.class);

        ResponseCookie newSession = loginResult.getResponseCookies().getFirst("SESSION");
        responseCookieState.replace("COOKIE", newSession);
    }

    @Test
    @Order(3)
    void when_approval_then_redirect_to_redirect_uri() {
        var session = responseCookieState.get("COOKIE");
        // approve or deny scopes
        String clientUrlPattern = ModelMocks.testClient().registeredRedirectUris().toArray()[0].toString() + "(.)+";
        FluxExchangeResult<Object> approveDenyScopes = authClient()
                .post()
                .uri(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .body(BodyInserters.fromFormData("read", "true")
                        .with("write", "true"))
                .cookie(session.getName(), session.getValue())
                .exchange()
                .expectStatus().isTemporaryRedirect()
                .expectHeader().valuesMatch("Location", clientUrlPattern)
                .returnResult(Object.class);

        ResponseCookie scopesSession = approveDenyScopes.getResponseCookies().getFirst("SESSION");
        responseCookieState.replace("COOKIE", scopesSession);
    }

    @Test
    @Order(4)
    void canGrantTokenWithAuthorizationCodeFlow() {
        // get token with authorization code
        FluxExchangeResult<OAuth2TokenResponse> tokenResponse = authClient()
                .post()
                .uri(TOKEN_ENDPOINT)
                .body(BodyInserters.
                        fromFormData("grant_type", "authorization_code")
                        .with("code", "generated_code")
                        .with("client_id", ModelMocks.testClient().clientId())
                        .with("redirect_uri", ModelMocks.testClient().registeredRedirectUris().toArray(new String[]{})[0])
                        .with("scopes", "read write")
                        .with("nonce", "random_nonce_string")
                        .with("state", "random_state"))
                .exchange()
                .expectStatus().isOk()
                .returnResult(OAuth2TokenResponse.class);

        StepVerifier.create(tokenResponse.getResponseBody())
                .assertNext(oAuth2TokenResponse -> {
                    assertThat(oAuth2TokenResponse.getScope()).isEqualTo("read write");
                    assertThat(oAuth2TokenResponse.getAccessToken()).isNotNull();
                    assertThat(oAuth2TokenResponse.getTokenType()).isEqualToIgnoringCase("bearer");
//                    assertThat(oAuth2TokenResponse.getRefreshToken()).isNotNull();
                })
                .verifyComplete();

    }

    @Test
    @Order(5)
    void when_anonymous_approval_then_redirect_to_redirect_uri() {
        // approve or deny scopes
        authClient()
                .post()
                .uri(getUriBuilder().replacePath(APPROVAL_ENDPOINT).build().toString())
                .body(BodyInserters
                        .fromFormData("read", "true")
                        .with("write", "true"))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .returnResult(Object.class);
    }
}
