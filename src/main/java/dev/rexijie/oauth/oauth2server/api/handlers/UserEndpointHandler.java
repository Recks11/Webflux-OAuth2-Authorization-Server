package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.error.ApiError;
import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import dev.rexijie.oauth.oauth2server.services.UserService;
import dev.rexijie.oauth.oauth2server.validation.UserValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.validation.Validator;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

@Component
public class UserEndpointHandler extends ApiEndpointHandler implements Handler<UserDTO> {
    private static final Logger LOG = LoggerFactory.getLogger(UserEndpointHandler.class);

    private final UserService userService;

    public UserEndpointHandler(UserService userService) {
        this.userService = userService;
    }


    public Mono<ServerResponse> saveUser(ServerRequest request) {
        return extractAndValidateDto(request)
                .flatMap(userService::addUser)
                .flatMap(userDTO -> ServerResponse.status(HttpStatus.CREATED).bodyValue(userDTO))
                .doOnError(err -> {
                    LOG.error("failure handling request {}", request.path());
                    LOG.debug("error handling request {} because: {}", request.path(), err.getMessage());
                    throw Exceptions.propagate(err);
                });
    }

    public Mono<ServerResponse> findUser(ServerRequest request) {
        return Mono.just(request)
                .map(req -> req.pathVariable("username"))
                .doOnError(err -> {
                    LOG.error("failure handling request {}", request.path());
                    LOG.debug("error handling request {} because: {}", request.path(), err.getMessage());
                    throw new ApiError(err, HttpStatus.BAD_REQUEST.value(), err.getMessage());
                })
                .flatMap(userService::findUserByUsername)
                .flatMap(dto -> ServerResponse.ok().bodyValue(dto));
    }

    @Override
    public Class<UserDTO> getInnerClass() {
        return UserDTO.class;
    }

    @Override
    public String getValidationKey() {
        return "user";
    }

    @Override
    public Validator getValidator() {
        return new UserValidator();
    }
}
