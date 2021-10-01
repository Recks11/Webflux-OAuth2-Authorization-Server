package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

public interface Signer {
    Mono<String> sign(JWTClaimsSet token);
}
