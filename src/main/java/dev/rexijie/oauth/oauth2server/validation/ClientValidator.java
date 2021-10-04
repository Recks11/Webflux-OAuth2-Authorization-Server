package dev.rexijie.oauth.oauth2server.validation;

import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import java.util.Collection;

public class ClientValidator implements Validator {
    private static final int MINIMUM_LENGTH = 1;

    public boolean supports(Class clazz) {
        return Client.class.isAssignableFrom(clazz);
    }

    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "clientName", "field.required");
        ClientDTO client = (ClientDTO) target;

        rejectValue(errors, client.getRedirectUris(), "redirectUris", "redirect uri");
        rejectValue(errors, client.getGrantTypes(), "grantTypes", "grant type");
        rejectValue(errors, client.getScopes(), "scopes", "scope");
        rejectValue(errors, client.getResourceIds(), "resourceIds", "resource id");
        rejectValue(errors, client.getAuthorities(), "authorities", "authority");
    }

    private void rejectValue(Errors errors, Collection<?> listField, String fieldName, String errorStr) {
        if (listField == null || listField.size() < 1)
            errors.rejectValue(fieldName, "field.min.length",
                    new Object[]{MINIMUM_LENGTH},
                    "at least [ %s ] %s must be provided".formatted(MINIMUM_LENGTH, errorStr));
    }
}
