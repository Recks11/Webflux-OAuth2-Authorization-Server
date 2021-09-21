package dev.rexijie.oauth.oauth2server.generators;

import java.security.*;

public class KeyGen {
    public static final String KEY_TYPE = "RSA";
    public static KeyPair generateKeys() throws NoSuchAlgorithmException {
        Provider provider = KeyFactory.getInstance(KEY_TYPE).getProvider();
        return KeyPairGenerator.getInstance(KEY_TYPE, provider).generateKeyPair();
    }
}
