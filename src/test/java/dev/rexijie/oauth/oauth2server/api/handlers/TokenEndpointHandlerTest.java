package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class TokenEndpointHandlerTest extends OAuthTest {

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