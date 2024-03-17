package dev.rexijie.oauth.oauth2server.error;

public class ApiError extends RuntimeException implements StatusAwareException {
    private final int status;
    private final String reason;

    public ApiError(Throwable cause, int status, String reason) {
        super(reason, cause);
        this.status = status;
        this.reason = reason;
    }

    public ApiError(int status, String reason) {
        super(reason);
        this.status = status;
        this.reason = reason;
    }

    public int getStatus() {
        return status;
    }

    public String getReason() {
        return reason;
    }
}
