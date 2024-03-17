package dev.rexijie.oauth.oauth2server.security.keys;

public interface KeyTuple<PRV_K, PUB_K> {

    PUB_K getPublic();
    PRV_K getPrivate();
}
