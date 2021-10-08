package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWT;
import reactor.core.publisher.Mono;

public interface JwtDeserializer {
     Mono<JWT> deserialize(String serializedJwt);
}
