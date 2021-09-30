package dev.rexijie.oauth.oauth2server.generators;

public interface CredentialsGenerator<T> {
    T generateCredentials();
}
