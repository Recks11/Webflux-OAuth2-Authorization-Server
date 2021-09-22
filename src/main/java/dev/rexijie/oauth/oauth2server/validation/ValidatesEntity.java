package dev.rexijie.oauth.oauth2server.validation;

import dev.rexijie.oauth.oauth2server.error.DtoValidationException;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Validator;
import reactor.core.Exceptions;

public interface ValidatesEntity<E> {
    String getValidationKey();

    Validator getValidator();

    default void validate(E dto) {
        BindingResult errors = new DtoValidationException(dto, getValidationKey());

        getValidator().validate(dto, errors);
        if (errors.hasErrors()) {
            throw Exceptions.propagate(new DtoValidationException(errors));
        }
    }
}
