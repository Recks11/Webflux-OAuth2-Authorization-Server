package dev.rexijie.oauth.oauth2server.api.handlers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class LoginAndApprovalHandler extends OAuthEndpointHandler {

    @Value("classpath:/templates/login.html")
    private Resource index;
    @Value("classpath:/templates/confirmaccess.html")
    private Resource approve;

    public Mono<ServerResponse> indexPage(ServerRequest request) {
        return ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue(index);
    }


    public Mono<ServerResponse> approvalPage(ServerRequest request) {
        return ServerResponse.ok()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue(index);
    }

    public Mono<ServerResponse> redirectToLogin(ServerRequest request) {
        return super.redirectTo(request, "/login");
    }
}
