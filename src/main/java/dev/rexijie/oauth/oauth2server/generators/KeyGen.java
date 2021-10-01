package dev.rexijie.oauth.oauth2server.generators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.security.*;

public class KeyGen {
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
}
