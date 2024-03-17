package dev.rexijie.oauth.oauth2server.api.handlers;

import dev.rexijie.oauth.oauth2server.validation.ValidatesEntity;
import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

public interface Handler<T> extends ValidatesEntity<T> {

    Class<T> getInnerClass();
    default Mono<T> extractAndValidateDto(ServerRequest request) {
        return request.bodyToMono(getInnerClass())
                .doOnNext(this::validate)
                .doOnError(err -> {throw Exceptions.propagate(err);});
    }
}
