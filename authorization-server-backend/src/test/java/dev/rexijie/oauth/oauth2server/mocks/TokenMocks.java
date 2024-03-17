package dev.rexijie.oauth.oauth2server.mocks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import dev.rexijie.oauth.oauth2server.security.keys.KeyPairStore;
import dev.rexijie.oauth.oauth2server.token.Signer;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class TokenMocks {

    public static PlainJWT getPlainToken() {
        return new PlainJWT(
                new PlainHeader.Builder()
                        .customParam(Signer.SIGNING_KEY_ID, KeyPairStore.DEFAULT_KEY_NAME)
                        .build(),
                new JWTClaimsSet.Builder()
                        .subject("rexijie")
                        .issuer(ServiceMocks.ConfigBeans.mockProperties().openId().issuer())
                        .audience(ModelMocks.testClient().clientId())
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(java.sql.Date.from(Instant.now().plus(10, ChronoUnit.SECONDS)))
                        .build()

        );
    }

    public static JWT getToken() {
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .build();
        return new SignedJWT(
                header,
                new JWTClaimsSet.Builder()
                        .subject("rexijie")
                        .issuer(ServiceMocks.ConfigBeans.mockProperties().openId().issuer())
                        .audience(ModelMocks.testClient().clientId())
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(java.sql.Date.from(Instant.now().plus(10, ChronoUnit.SECONDS)))
                        .build()
        );
    }
}
