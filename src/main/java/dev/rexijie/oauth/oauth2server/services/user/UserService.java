package dev.rexijie.oauth.oauth2server.services.user;

import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<UserDTO> findUserByUsername(String username);
    Mono<UserDTO> addUser(UserDTO user);
}
