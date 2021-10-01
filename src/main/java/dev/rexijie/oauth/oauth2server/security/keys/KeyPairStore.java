package dev.rexijie.oauth.oauth2server.security.keys;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyPairStore<PK, OK> {

    String getId();
    KeyPairContainer getDefault();
    KeyPairContainer getKeyPair(String id);
    PK getPrivateKey(String id);
    OK getPublicKey(String id);
    String addKeyPair(KeyPair keyPair, String keyUse, String alg) throws KeyStoreException;
    void removeKeyPair(String keyID);
}
