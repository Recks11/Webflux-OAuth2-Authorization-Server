package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWT;
import reactor.core.publisher.Mono;

public interface Verifier {
    Mono<Boolean> verify(String token);
    Mono<Void> verifyClaims(JWT token, OAuth2Authentication authentication);
}
