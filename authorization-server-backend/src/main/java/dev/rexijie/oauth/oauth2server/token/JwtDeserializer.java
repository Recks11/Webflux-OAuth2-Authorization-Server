package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import reactor.core.publisher.Mono;

public interface JwtDeserializer {
     Mono<JWT> deserialize(String serializedJwt);
}
