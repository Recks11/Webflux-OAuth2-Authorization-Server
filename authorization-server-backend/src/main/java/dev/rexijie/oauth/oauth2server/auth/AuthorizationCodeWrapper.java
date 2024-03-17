package dev.rexijie.oauth.oauth2server.auth;

/**
 * Interface to represent serialised authentication.
 * the Authentication is represented as a byte[]
 * and can be converted to the required format
 */
public interface AuthorizationCodeWrapper {
    String getCode();

    String getApprovalToken();

    byte[] getAuthentication();

}
