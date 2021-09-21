package dev.rexijie.oauth.oauth2server.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DefaultClientServiceTest {

    Map<String, String> st = new HashMap<>();
    @BeforeEach
    void setUp() {
    }

    @Test
    void createClient() {
        st.put("Rex", "Data is here");
        Mono.fromCallable(() -> st.get("sge"))
                .doOnNext(o -> System.out.println("Empty has an onNext"))
                .switchIfEmpty(Mono.just(st.get("Rex")))
                        .doOnNext(System.out::println)
                        .subscribe();
    }

    @Test
    void findClientById() {
    }

    @Test
    void findClientByWithCredentials() {
    }
}