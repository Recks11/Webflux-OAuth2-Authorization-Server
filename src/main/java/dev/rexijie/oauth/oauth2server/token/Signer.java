package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jwt.JWT;
import reactor.core.publisher.Mono;


public interface Signer extends JwtDeserializer, Verifier {
    String SIGNING_KEY_ID = "dev.rexijie.signing.key";
    Mono<String> sign(JWT token);
}
