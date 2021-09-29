package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

class OpenIdConnectHandlerTest extends OAuthTest {

    @Test
    void whenGetOpenIdProperties_thenOk() {
        authClient()
                .get()
                .uri("/openid/.well-known/openid-configuration")
                .exchange()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectStatus().isOk()
                .expectBody().jsonPath("$").isNotEmpty();
    }

    @Test
    void whenGetJwkSet_thenSuccess() {
        authClient()
                .get()
                .uri("/openid/.well-known/jwks.json")
                .exchange()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.keys")
                .isNotEmpty();
    }
}