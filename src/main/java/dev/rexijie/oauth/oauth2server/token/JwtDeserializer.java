package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.SignedJWT;
import reactor.core.publisher.Mono;

public interface JwtDeserializer {
     Mono<SignedJWT> deserialize(String serializedJwt);
}
