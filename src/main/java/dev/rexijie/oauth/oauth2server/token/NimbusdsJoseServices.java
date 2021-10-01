package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairContainer;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static dev.rexijie.oauth.oauth2server.security.keys.InMemoryRSAKeyPairStore.DEFAULT_KEY;

public class NimbusdsJoseServices implements Signer {

    @Autowired
    private KeyPairStore<RSAPrivateKey, RSAPublicKey> keyPairStore;

    public RSAKey getDefaultKey() {
        var container = keyPairStore.getKeyPair(DEFAULT_KEY);
        return (RSAKey) buildKey(container);
    }

    @Override
    public Mono<String> sign(JWTClaimsSet token) {
        return Mono.just(keyPairStore)
                .map(kps -> buildKey(kps.getDefault()))
                .cast(RSAKey.class)
                .zipWith(Mono.just(token), (key, jwtClaimsSet) -> {
                    RSASSASigner signer = createSignerForRSAKey(key);
                    var jwt = new SignedJWT(
                            buildHeader(key),
                            jwtClaimsSet
                    );
                    try {
                        jwt.sign(signer);
                        return jwt.serialize();
                    } catch (JOSEException e) {
                        throw Exceptions.propagate(e);
                    }
                });
    }

    public Mono<Boolean> verifyJWT(String token, RSAKey rsaPublicJWK) {
        return Mono.create(monoSink -> {
            // On the consumer side, parse the JWS and verify its RSA signature
            try {
                var signedJWT = SignedJWT.parse(token);
                JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
                monoSink.success(signedJWT.verify(verifier));
            } catch (ParseException e) {
                monoSink.error(JWKException.expectedClass(RSAKey.class));
            } catch (JOSEException exception) {
                monoSink.error(new JwtException("invalid token", exception));
            }
        });

        // Retrieve / verify the JWT claims according to the app requirements
//        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
//        assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
//        assertTrue(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    private Mono<JWTClaimsSet> convertClaims(Jwt token) {
//        var claims = new HashMap(token.);
        return Mono.create(monoSink -> {
            try {
                JWTClaimsSet.parse(token.toString());
            } catch (ParseException exception) {
                monoSink.error(exception);
            }
        });
    }

    // Create RSA-signer with the private key
    private RSASSASigner createSignerForRSAKey(RSAKey key) {
        try {
            return new RSASSASigner(key);
        } catch (JOSEException exception) {
            exception.printStackTrace();
        }
        return null;
    }

    private JWK buildKey(KeyPairContainer container) {
        KeyUse keyUse;
        try {
            keyUse = KeyUse.parse(container.getKeyUse());
        } catch (ParseException e) {
            keyUse = KeyUse.SIGNATURE;
        }
        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) container.getPublic())
                .privateKey(container.getPrivate())
                .keyUse(keyUse)
                .algorithm(JWSAlgorithm.parse(container.getKeyAlgorithm()))
                .keyID(container.getId());

        return builder.build();
    }

    private JWSHeader buildHeader(RSAKey key) {
        return new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.getKeyID())
                .build();
    }

//    static class JWKSignerFactory {
//        Map<String, >
//    }
}
