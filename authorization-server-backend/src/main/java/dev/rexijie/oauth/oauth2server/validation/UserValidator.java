package dev.rexijie.oauth.oauth2server.validation;


import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

public class UserValidator implements Validator {

    private static final int MINIMUM_LENGTH = 1;

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(UserDTO.class);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "field.required");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "password", "field.required");
        UserDTO userdto = (UserDTO) target;

        if (userdto.getAuthorities().size() < 1) {
            errors.rejectValue("authorities", "field.min.length",
                    new Object[]{MINIMUM_LENGTH},
                    "at least [" + MINIMUM_LENGTH + "] authority must be provided");
        }
    }
}
