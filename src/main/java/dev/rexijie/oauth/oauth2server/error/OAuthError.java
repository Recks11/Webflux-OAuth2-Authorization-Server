package dev.rexijie.oauth.oauth2server.error;


import org.springframework.http.HttpStatus;

public class OAuthError extends RuntimeException implements StatusAwareException {
    public static OAuthError INVALID_REQUEST_ERROR = new OAuthError(OAuthErrors.INVALID_REQUEST);
    public static OAuthError INVALID_CLIENT_ERROR = new OAuthError(OAuthErrors.INVALID_CLIENT);
    public static OAuthError INVALID_GRANT_ERROR = new OAuthError(OAuthErrors.INVALID_GRANT);
    public static OAuthError UNAUTHORIZED_CLIENT_ERROR = new OAuthError(OAuthErrors.UNAUTHORIZED_CLIENT);
    public static OAuthError UNSUPPORTED_GRANT_TYPE_ERROR = new OAuthError(OAuthErrors.UNSUPPORTED_GRANT_TYPE);
    public static OAuthError INVALID_SCOPE_ERROR = new OAuthError(OAuthErrors.INVALID_SCOPE);
    private final int status;
    private final String error;
    private final String errorDescription;

    public OAuthError(OAuthErrors errorEnum) {
        super(errorEnum.getError());
        this.status = errorEnum.getStatus();
        this.error = errorEnum.getError();
        this.errorDescription = errorEnum.getErrorDescription();
    }

    public OAuthError(OAuthErrors errorEnum, Throwable cause) {
        super(cause);
        this.status = errorEnum.getStatus();
        this.error = errorEnum.getError();
        this.errorDescription = errorEnum.getErrorDescription();
    }

    public OAuthError(Throwable cause, String error, String errorDescription) {
        super(error, cause);
        this.status = HttpStatus.UNAUTHORIZED.value();
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public OAuthError(Throwable cause, int status, String error, String errorDescription) {
        super(error, cause);
        this.status = status;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public int getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public enum OAuthErrors {
        INVALID_REQUEST(HttpStatus.BAD_REQUEST, "invalid_request", "The request is missing some parameters"),
        INVALID_CLIENT(HttpStatus.BAD_REQUEST, "invalid_client", "Client authentication failed"),
        INVALID_GRANT(HttpStatus.BAD_REQUEST, "invalid_grant", "credentials expired"),
        UNAUTHORIZED_CLIENT(HttpStatus.BAD_REQUEST, "unauthorized_client",
                "The authenticated client is not authorized to use this authorization grant type"),
        UNSUPPORTED_GRANT_TYPE(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                "The authorization grant type is not supported by the authorization server."),
        INVALID_SCOPE(HttpStatus.BAD_REQUEST, "invalid_scope", "requested scope is invalid");


        private final int status;
        private final String error;
        private final String errorDescription;

        OAuthErrors(HttpStatus status, String error, String errorDescription) {
            this.status = status.value();
            this.error = error;
            this.errorDescription = errorDescription;
        }

        public int getStatus() {
            return status;
        }

        public String getError() {
            return error;
        }

        public String getErrorDescription() {
            return errorDescription;
        }
    }
}
