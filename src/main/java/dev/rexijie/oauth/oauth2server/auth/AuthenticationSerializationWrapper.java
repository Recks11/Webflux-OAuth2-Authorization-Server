package dev.rexijie.oauth.oauth2server.auth;

public class AuthenticationSerializationWrapper {
    private final String code;
    private final byte[] authentication;
    private final String approvalToken;

    public AuthenticationSerializationWrapper(String code, String approvalToken, byte[] authentication) {
        this.code = code;
        this.approvalToken = approvalToken;
        this.authentication = authentication;
    }

    public String getCode() {
        return code;
    }

    public String getApprovalToken() {
        return approvalToken;
    }

    public byte[] getAuthentication() {
        return authentication;
    }

    public void onConsume() {

    }
}
