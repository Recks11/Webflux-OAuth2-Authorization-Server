package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.ApiTest;
import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.util.Map;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.testClient;
import static org.junit.jupiter.api.Assertions.*;

class ClientEndpointHandlerTest extends ApiTest {

    @Test
    void whenCreateClientWithValidClient_thenSuccess() {
        authClient()
                .post()
                .uri("/api/client")
                .body(Mono.just(ClientDTO.ClientMapper.toDto(testClient())), ClientDTO.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.client_id").isNotEmpty()
                .jsonPath("$.client_secret").isNotEmpty();

    }

    @Test
    void whenCreateClientWithInvalidClient_thenBadRequest() {
        authClient()
                .post()
                .uri("/api/client")
                .body(BodyInserters.fromValue(Map.of(
                        "client_name", "badClient",
                        "client_id", "sus id",
                        "client_secret", "sus secret"
                )))
                .exchange()
                .expectStatus().isBadRequest();
    }
}