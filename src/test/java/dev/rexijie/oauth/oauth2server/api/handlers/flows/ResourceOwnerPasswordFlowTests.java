package dev.rexijie.oauth.oauth2server.api.handlers.flows;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.BodyInserters;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ResourceOwnerPasswordFlowTests extends OAuthTest {

    @Test
    void whenEndUserClientCredentialsFlow_ThenSuccess() {
        authClient()
                .post()
                .uri(TOKEN_ENDPOINT)
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
                    assertNotNull(result.getResponseBody());
                    assertNotNull(result.getResponseBody().getAccessToken());
                    assertTrue(result.getResponseBody().getExpiresIn() > 0);
                    assertThat(result.getResponseBody().getScope()).contains("read");
                });
    }
}