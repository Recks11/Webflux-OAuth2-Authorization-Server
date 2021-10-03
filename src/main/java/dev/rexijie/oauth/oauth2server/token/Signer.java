package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWTClaimsSet;
import reactor.core.publisher.Mono;

public interface Signer {
    Mono<String> sign(JWTClaimsSet token);
}
