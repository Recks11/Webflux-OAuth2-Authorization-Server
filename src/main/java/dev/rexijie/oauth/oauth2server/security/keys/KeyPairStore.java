package dev.rexijie.oauth.oauth2server.security.keys;

import dev.rexijie.oauth.oauth2server.generators.RandomStringSecretGenerator;

import java.security.KeyPair;
import java.security.KeyStoreException;

public interface KeyPairStore<PK, OK> {
    String DEFAULT_KEY_NAME = new RandomStringSecretGenerator().generate(12);
    boolean canStore(KeyPairContainer container);
    String getId();
    KeyPairContainer getDefault();
    KeyPairContainer getKeyPair(String id);
    PK getPrivateKey(String id);
    OK getPublicKey(String id);
    String addKeyPair(KeyPair keyPair, String keyUse, String alg) throws KeyStoreException;
    void removeKeyPair(String keyID);
}
