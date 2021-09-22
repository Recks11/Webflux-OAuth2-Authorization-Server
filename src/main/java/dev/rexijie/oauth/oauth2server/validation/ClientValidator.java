package dev.rexijie.oauth.oauth2server.validation;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

public class ClientValidator implements Validator {
    private static final int MINIMUM_LENGTH = 1;

    public boolean supports(Class clazz) {
        return Client.class.isAssignableFrom(clazz);
    }

    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "clientName", "field.required");
        ClientDTO client = (ClientDTO) target;

        if (client.getGrantTypes().size() < 1) {
            errors.rejectValue("authorizedGrantTypes", "field.min.length",
                    new Object[]{MINIMUM_LENGTH},
                    "at least [" + MINIMUM_LENGTH + "] grant type must be provided");
        }
    }
}
