package dev.rexijie.oauth.oauth2server.generators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;

import java.security.*;

public class KeyGen {
    private static final Logger LOG = LoggerFactory.getLogger(KeyGen.class);
    public static final String KEY_TYPE = "RSA";
    public static KeyPair generateKeys() {
        try {
            Provider provider = KeyFactory.getInstance(KEY_TYPE).getProvider();
            return KeyPairGenerator.getInstance(KEY_TYPE, provider).generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            return generateRSAKeys();
        }
    }


    public static KeyPair generateRSAKeys() {
        try {
            RSAKey rsaJWK = new RSAKeyGenerator(2048)
                    .keyID("123")
                    .generate();
            return rsaJWK.toKeyPair();
        } catch (JOSEException exception) {
            throw new Error("unable to create keypair");
            // or get from file system?
        }
    }

    public static JWK generateRSAJWK() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyIDFromThumbprint(true)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (JOSEException e) {
            LOG.error("failed to generate RSA JWK", e);
            throw Exceptions.propagate(e);
        }
    }

    public static JWK generateECKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyIDFromThumbprint(true)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (JOSEException e) {
            LOG.error("failed to generate EC JWK", e);
            throw Exceptions.propagate(e);
        }
    }

}
