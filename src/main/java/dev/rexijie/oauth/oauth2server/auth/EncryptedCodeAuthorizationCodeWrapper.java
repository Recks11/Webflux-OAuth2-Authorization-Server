package dev.rexijie.oauth.oauth2server.auth;

public class EncryptedCodeAuthorizationCodeWrapper implements AuthorizationCodeWrapper {
    private final String code;
    private final byte[] authentication;
    private final String approvalToken;

    public EncryptedCodeAuthorizationCodeWrapper(String code, byte[] authentication) {
        this.code = code;
        this.approvalToken = null;
        this.authentication = authentication;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getApprovalToken() {
        return approvalToken;
    }

    @Override
    public byte[] getAuthentication() {
        return authentication;
    }

    @Override
    public String toString() {
        return "EncryptedCodeAuthorizationCodeWrapper {" +
                "code='" + code + '\'' +
                '}';
    }
}
