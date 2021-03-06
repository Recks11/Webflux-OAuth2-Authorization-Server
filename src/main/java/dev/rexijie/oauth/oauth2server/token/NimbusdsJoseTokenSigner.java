package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import dev.rexijie.oauth.oauth2server.config.OAuth2Properties;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairContainer;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.token.verifier.UserTokenClaimsVerifierFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static dev.rexijie.oauth.oauth2server.util.JoseUtils.assertInstance;

public class NimbusdsJoseTokenSigner implements Signer {

    private final KeyPairStore<RSAPrivateKey, RSAPublicKey> keyPairStore;
    private final JWSSignerFactory jwsSignerFactory = new DefaultJWSSignerFactory();
    private final JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();
    //    private final DefaultJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor<>();
    private final UserTokenClaimsVerifierFactory claimsVerifierFactory =
            new UserTokenClaimsVerifierFactory();
    private final OAuth2Properties properties;

    public NimbusdsJoseTokenSigner(KeyPairStore<RSAPrivateKey, RSAPublicKey> keyPairStore,
                                   OAuth2Properties oAuth2Properties) {
        this.keyPairStore = keyPairStore;
        this.properties = oAuth2Properties;
    }

    @Override
    public Mono<String> sign(JWT token) {
        return createSignatureContext((PlainJWT) token)
                .map(context -> {
                    var jwt = new SignedJWT(
                            populateHeader(context),
                            context.getClaimsSet());
                    try {
                        jwt.sign(context.getSigner());
                        return jwt.serialize();
                    } catch (JOSEException e) {
                        throw Exceptions.propagate(e);
                    }
                });

    }

    @Override
    public Mono<String> sign(String token) {
        return deserialize(token)
                .map(jwt -> assertInstance(jwt, PlainJWT.class))
                .flatMap(this::sign);
    }

    @Override
    public Mono<JWT> deserialize(String serializedJwt) {
        return Mono.create(monoSink -> {
            try {
                JWT parsedToken = JWTParser.parse(serializedJwt);
                monoSink.success(parsedToken);
            } catch (ParseException exception) {
                monoSink.error(new JwtException("invalid token", exception));
            }
        });
    }

    public Mono<Boolean> verify(String token) {
        return deserialize(token)
                .map(jwt -> assertInstance(jwt, SignedJWT.class))
                .flatMap(signedJWT -> Mono.create(monoSink -> {
                    try {
                        var key = keyPairStore.getKeyPair(signedJWT.getHeader().getKeyID());
                        JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key.getPublic());
                        monoSink.success(signedJWT.verify(verifier));
                    } catch (JOSEException e) {
                        monoSink.error(new JwtException("invalid token", e));
                    }
                }));
    }

    @Override
    public Mono<Void> verifyClaims(JWTClaimsSet claimsSet, OAuth2Authentication authentication) {
        return Mono.create(monoSink -> {
            try {
                var audience = authentication.getPrincipal().toString();
                JWTClaimsSetVerifier<?> claimsSetVerifier = claimsVerifierFactory.getVerifier(audience,
                        properties.openId().issuer());
                claimsSetVerifier.verify(claimsSet, null);
                monoSink.success();
            } catch (BadJWTException ex) {
                monoSink.error(new JwtException("invalid jwt", ex));
            }
        });

    }

    private JWSHeader populateHeader(KeySigningContext context) {

        return new JWSHeader.Builder(context.getAlgorithm())
                .keyID(context.getParsedKey().getKeyID())
                .build();
    }

    private Mono<KeySigningContext> createSignatureContext(PlainJWT token) {
        return Mono.just(new KeySigningContext(token))
                .map(keySigningContext -> {
                    var id = token.getHeader().getCustomParam(SIGNING_KEY_ID).toString();
                    keySigningContext.setContainer(keyPairStore.getKeyPair(id));
                    return keySigningContext;
                })
                .flatMap(this::populateContext);
    }

    private Mono<KeySigningContext> populateContext(KeySigningContext context) {
        var container = context.getContainer();
        return Mono.fromCallable(() -> KeyUse.parse(container.getKeyUse()))
                .onErrorResume(throwable -> Mono.just(KeyUse.SIGNATURE))
                .map(keyUse -> {
                    try {
                        var key = getKey(context, keyUse);
                        context.setParsedKey(key);
                        return context;
                    } catch (BadJWSException e) {
                        throw Exceptions.propagate(e);
                    }
                }).map(ctx -> {
                    ctx.setSigner(createSignerForKey(ctx.parsedKey));
                    return ctx;
                });
    }

    // Create RSA-signer with the private key
    private JWSSigner createSignerForKey(JWK key) {
        try {
            return jwsSignerFactory.createJWSSigner(key);
        } catch (JOSEException exception) {
            throw Exceptions.propagate(exception);
        }
    }

    // build the signing key for the context with the provided use
    private JWK getKey(KeySigningContext context, KeyUse keyUse) throws BadJWSException {
        var container = context.getContainer();
        String alg = container.getKeyAlgorithm();
        return switch (alg) {
            case "RS256", "RS384", "RS512" -> buildRSAKey(container, keyUse);
            default -> throw new BadJWSException("Unsupported JWS signature");
        };
    }

    private RSAKey buildRSAKey(KeyPairContainer container, KeyUse keyUse) {
        return new RSAKey.Builder((RSAPublicKey) container.getPublic())
                .privateKey(container.getPrivate())
                .keyUse(keyUse)
                .algorithm(JWSAlgorithm.parse(container.getKeyAlgorithm()))
                .keyID(container.getId()).build();
    }

    private static final class KeySigningContext {
        private KeyPairContainer container;
        private final PlainJWT token;
        private JWSAlgorithm algorithm;
        private JWSSigner signer;
        private JWK parsedKey;

        private KeySigningContext(PlainJWT token) {
            this.token = token;
        }

        public KeyPairContainer getContainer() {
            return container;
        }

        public void setContainer(KeyPairContainer container) {
            this.container = container;
            this.algorithm = JWSAlgorithm.parse(container.getKeyAlgorithm());
        }

        public JWSAlgorithm getAlgorithm() {
            return algorithm;
        }

        public PlainJWT getToken() {
            return token;
        }

        public JWTClaimsSet getClaimsSet() {
            try {
                return token.getJWTClaimsSet();
            } catch (ParseException exception) {
                throw Exceptions.propagate(exception);
            }
        }

        public JWK getParsedKey() {
            return parsedKey;
        }

        public void setParsedKey(JWK parsedKey) {
            this.parsedKey = parsedKey;
        }

        public JWSSigner getSigner() {
            return signer;
        }

        public void setSigner(JWSSigner signer) {
            this.signer = signer;
        }
    }
}
