package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.testUser;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class UserEndpointHandlerTest extends OAuthTest {

    @Test
    void whenCreateUserWithValidUser_thenSuccess() {
        when(userRepository.findByUsername(any(String.class)))
                .thenReturn(Mono.empty());

        var user = testUser();
        user.setEmail("dev@email.com");
        user.setUsername("devee");
        authClient()
                .post()
                .uri("/api/users")
                .body(Mono.just(UserDTO.UserDTOMapper.toDto(user)), UserDTO.class)
                .exchange()
                .expectStatus().isCreated()
                .expectBody();
    }

    @Test
    void whenFindUser_thenOk() {
        authClient()
                .get()
                .uri("/api/users/%s".formatted(testUser().getUsername()))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$").isNotEmpty();
    }
}