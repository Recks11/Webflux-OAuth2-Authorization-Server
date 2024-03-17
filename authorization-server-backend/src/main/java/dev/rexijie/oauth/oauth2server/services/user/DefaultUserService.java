package dev.rexijie.oauth.oauth2server.services.user;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.error.ApiError;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.dto.UserDTO;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.util.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;
import java.util.UUID;

import static java.time.ZoneOffset.UTC;

@Component
public class DefaultUserService implements UserService {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultUserService.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    public DefaultUserService(UserRepository userRepository,
                              PasswordEncoder passwordEncoder,
                              ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<UserDTO> findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.error(new ApiError(
                        HttpStatus.NOT_FOUND.value(), "the requested user does not exist")))
                .map(UserDTO.UserDTOMapper::toDto)
                .doOnError(ExceptionUtils::propagate);
    }

    // TODO validate user
    public Mono<UserDTO> addUser(UserDTO userDto) {
        return validateDto(userDto)
                .flatMap(userDTO -> userRepository.findByUsername(userDTO.getUsername())
                        .doOnNext(usr -> {
                            throw new ApiError(HttpStatus.BAD_REQUEST.value(), "user already exists");
                        })
                        .map(UserDTO.UserDTOMapper::toDto)
                        .switchIfEmpty(Mono.just(encodePassword(userDto)))
                        .flatMap(encodedPasswordUserDto -> {
                            User user = createUser(UserDTO.UserDTOMapper.toUser(encodedPasswordUserDto));
                            return userRepository.save(user)
                                    .map(UserDTO.UserDTOMapper::toDto);
                        })
                        .doOnError(ExceptionUtils::propagate));
    }

    private UserDTO encodePassword(UserDTO userDto) {
        return new UserDTO(
                userDto.getUsername(), passwordEncoder.encode(userDto.getPassword()),
                userDto.getEmail(), userDto.getAuthorities());
    }

    private User createUser(User user) {
        final var createdAt = LocalDateTime.now(ZoneId.of(UTC.getId()));
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(createdAt);
        user.setId(UUID.randomUUID().toString());
        LOG.info("Created User: {}", user);
        return encryptFields(user);
    }

    private User encryptFields(User user) {
        try {
            Map<String, Object> userString = objectMapper.convertValue(user, new TypeReference<>() {});
//            LOG.info("Converted user: {}", userString);
        } catch (Exception exception) {
            LOG.error(exception.getMessage());
        }
        return user;
    }

    private Mono<UserDTO> validateDto(UserDTO userDTO) {
        return Mono.just(userDTO);
    }
}
