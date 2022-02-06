package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWTClaimsSet;
import reactor.core.publisher.Mono;

public interface Verifier {
    Mono<Boolean> verify(String token);
    Mono<Void> verifyClaims(JWTClaimsSet token, OAuth2Authentication authentication);
}
