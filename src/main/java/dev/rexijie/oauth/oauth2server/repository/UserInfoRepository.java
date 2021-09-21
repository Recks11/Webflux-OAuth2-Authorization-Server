package dev.rexijie.oauth.oauth2server.repository;

import dev.rexijie.oauth.oauth2server.model.UserInfo;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface UserInfoRepository extends ReactiveMongoRepository<UserInfo, String> {
    Mono<UserInfo> findByUserId(String id);
}
