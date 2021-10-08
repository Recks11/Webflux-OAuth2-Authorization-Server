package dev.rexijie.oauth.oauth2server.utils;

import org.mockito.internal.stubbing.answers.ReturnsArgumentAt;
import org.mockito.stubbing.Answer;
import reactor.core.publisher.Mono;

public class TestUtils {
    public static Answer<?> returnsMonoAtArg() {
        return invocation -> {
            ReturnsArgumentAt returnsArgumentAt = new ReturnsArgumentAt(0);
//            returnsArgumentAt.validateFor(invocation);
            Object answer = returnsArgumentAt.answer(invocation);
            return Mono.just(answer);
        };
    }
    public static Answer<?> returnsMonoAtArg(int position) {
        return invocation -> {
            ReturnsArgumentAt returnsArgumentAt = new ReturnsArgumentAt(position);
//            returnsArgumentAt.validateFor(invocation);
            Object answer = returnsArgumentAt.answer(invocation);
            return Mono.just(answer);
        };
    }
}
