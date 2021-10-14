package dev.rexijie.oauth.oauth2server.api.handlers.flows;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.api.domain.OAuth2TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.BodyInserters;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;

public class ClientCredentialsFlowTest extends OAuthTest {
    @Override
    public void setUp() {

    }

    @Test
    void canGrantTokenWithClientCredentials() {
        apiClient()
                .post()
                .uri(TOKEN_ENDPOINT)
                .body(BodyInserters
                        .fromFormData(GRANT_TYPE, "client_credentials")
                        .with(SCOPE, "read")
                        .with(CLIENT_ID, "test-client")
                        .with(CLIENT_SECRET, "secret")
                ).exchange()
                .expectBody(OAuth2TokenResponse.class)
                .consumeWith(res -> {
                    var response = res.getResponseBody();
                    assertThat(response).isNotNull()
                            .extracting(OAuth2TokenResponse::getAccessToken)
                            .isNotNull();
                });
    }
}
