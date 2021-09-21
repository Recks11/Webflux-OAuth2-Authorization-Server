package dev.rexijie.oauth.oauth2server.services;

public interface CredentialsGenerator<T> {
    T generateCredentials();
}
