package dev.rexijie.oauth.oauth2server.security.keys;

import dev.rexijie.oauth.oauth2server.generators.KeyGen;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public final class RSAKeyTuple implements KeyTuple<RSAPrivateKey, RSAPublicKey> {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public RSAKeyTuple() {
        this(KeyGen.generateKeys());
    }

    public RSAKeyTuple (KeyPair keyPair) {
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    public RSAKeyTuple(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public RSAPublicKey getPublic() {
        return this.publicKey;
    }

    @Override
    public RSAPrivateKey getPrivate() {
        return this.privateKey;
    }
}
