package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.ApiTest;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class TokenEndpointHandlerTest extends ApiTest {

    @Test
    void whenCreateEndUserClientCredentialsFlow_ThenSuccess() {
        authClient()
                .post()
                .uri("/oauth/token")
                .body(
                        BodyInserters
                                .fromFormData("grant_type", "password")
                                .with("username", getDefaultUser().getUsername())
                                .with("password", "password")
                                .with("scopes", "read"))
                .exchange()
                .expectStatus().isOk()
                .expectBody(OAuth2TokenResponse.class)
                .consumeWith(result -> {
                    assertNotNull(result.getResponseBody().getAccessToken());
                    assertTrue(result.getResponseBody().getExpiresIn() > 0);
                    assertThat(result.getResponseBody().getScope()).contains("read");
                });
    }

    @Test
    void whenGetTokenKey_thenSuccess() {
        authClient()
                .get()
                .uri("/oauth/token_key")
                .exchange()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.keys")
                .isNotEmpty();
    }
}