package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.junit.jupiter.api.Assertions.*;

@WebFluxTest
class OpenIdConnectHandlerTest {

    @Autowired
    private OAuth2Properties oAuth2Properties;

    @Test
    void getOpenIdProperties() {
        System.out.println(oAuth2Properties.toString());
    }

    @Test
    void getJwkSet() {
    }
}