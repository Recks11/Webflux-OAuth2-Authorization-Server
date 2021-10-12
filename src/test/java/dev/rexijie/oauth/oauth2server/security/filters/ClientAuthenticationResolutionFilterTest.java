package dev.rexijie.oauth.oauth2server.security.filters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.Principal;
import java.util.Base64;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class ClientAuthenticationResolutionFilterTest {

    @BeforeEach
    void setUp() {
    }

    @Test
    void filter() {
        WebFilter webFilter = new ClientAuthenticationResolutionFilter();
        UriBuilder pathBuilder = new DefaultUriBuilderFactory().builder()
                .host("localhost")
                .port("8080")
                .scheme("http")
                .path("/oauth/authorize")
                .queryParam("grant_type", "authorization_code")
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", "http://localhost:8900/oauth/code/")
                .queryParam("client_id", "test-client")
                .queryParam("scopes", "read write")
                .queryParam("state", "random_state")
                .queryParam("nonce", "random_nonce_string");
        var request = MockServerHttpRequest
                .get(pathBuilder.build().toString())
                .header("Authorization", "basic %s".formatted(basic()))
                .build();

        var exchange = new MockServerWebExchange.Builder(request)
                .build();

        Mono<Void> filter = webFilter.filter(exchange, exchange1 -> Mono.empty());

        StepVerifier.create(filter)
                .verifyComplete();


    }

    private String basic() {
            return Base64.getEncoder().encodeToString(
                    "test-client:secret".getBytes()
            );
    }
}