package dev.rexijie.oauth.oauth2server.token;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.mint.DefaultJWSMinter;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.text.ParseException;

public class NimbusJOSETokenProcessor extends DefaultJWTProcessor<SecurityContext> implements Signer {
    private final DefaultJWSMinter<SecurityContext> minter;

    public NimbusJOSETokenProcessor(JWSKeySelector<SecurityContext> keySelector,
                                    JWKSource<SecurityContext> jwkSource) {
        this.setJWSKeySelector(keySelector);
        this.minter = new DefaultJWSMinter<>();
        this.minter.setJWKSource(jwkSource);
    }

    @Override
    public Mono<String> sign(JWT token) {
        return Mono.just(token)
                .cast(SignedJWT.class)
                .map(signed -> {
                    try {
                        var minted = minter.mint(
                                signed.getHeader(),
                                signed.getJWTClaimsSet().toPayload(),
                                null);
                        return minted.serialize();
                    } catch (Exception e) {
                        throw Exceptions.propagate(e);
                    }
                });

    }

    @Override
    public Mono<String> sign(String token) {
        return deserialize(token)
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
        return Mono.fromCallable(() -> process(token, null))
                .doOnError(e -> {throw Exceptions.propagate(e);})
                .map(claimsSet -> true)
                .onErrorReturn(false);
    }

    @Override
    public Mono<Void> verifyClaims(JWTClaimsSet claimsSet, OAuth2Authentication authentication) {
        return Mono.create(monoSink -> {
            try {
//                var audience = authentication.getPrincipal().toString();
//                private final UserTokenClaimsVerifierFactory claimsVerifierFactory =
//                        new UserTokenClaimsVerifierFactory();
//                JWTClaimsSetVerifier<?> claimsVerifier = claimsVerifierFactory.getVerifier(audience, properties.openId().issuer());
                getJWTClaimsSetVerifier().verify(claimsSet, null);
                monoSink.success();
            } catch (BadJWTException e) {
                monoSink.error(new JwtException("invalid jwt", e));
            }
        });

    }
}
