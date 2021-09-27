package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.ApiTest;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.testClient;
import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.testUser;
import static org.junit.jupiter.api.Assertions.*;

class UserEndpointHandlerTest extends ApiTest {

    @Test
    void whenCreateUserWithValidUser_thenSuccess() {
        authClient()
                .post()
                .uri("/api/users")
                .body(Mono.just(UserDTO.UserDTOMapper.toDto(testUser())), UserDTO.class)
                .exchange()
                .expectStatus().isOk()
                .expectBody();

    }

    @Test
    void whenFindUser_thenOk() {
        authClient()
                .get()
                .uri("/api/users/id")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$").isNotEmpty();
    }
}