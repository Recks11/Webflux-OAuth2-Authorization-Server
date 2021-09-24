package dev.rexijie.oauth.oauth2server.security.keys;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyPairStore {

    String getId();
    <K1 extends PrivateKey> K1 getPrivateKey(Class<K1> keyClass);
    <K2 extends PublicKey> K2 getPublicKey(Class<K2> keyClass);
}
