package dev.rexijie.oauth.oauth2server.error;

import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;

public class DtoValidationException extends BindException implements StatusAwareException {
    private final HttpStatus status = HttpStatus.BAD_REQUEST;

    public DtoValidationException(BindingResult bindingResult) {
        super(bindingResult);
    }

    public DtoValidationException(Object target, String objectName) {
        super(target, objectName);
    }

    public int getStatus() {
        return status.value();
    }
}
