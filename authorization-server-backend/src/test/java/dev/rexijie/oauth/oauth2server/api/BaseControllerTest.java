package dev.rexijie.oauth.oauth2server.api;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;


class BaseControllerTest extends OAuthTest {

    @Test
    void whenGetIndexPage_thenSuccess() {
        apiClient()
                .get()
                .uri("/login")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.TEXT_HTML);
    }

    @Override
    public void setUp() {

    }
}