package dev.rexijie.oauth.oauth2server.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import org.apache.avro.Schema;
import org.apache.avro.io.DatumWriter;
import org.apache.avro.io.Encoder;
import org.apache.avro.io.EncoderFactory;
import org.apache.avro.reflect.ReflectData;
import org.apache.avro.reflect.ReflectDatumWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SerializationUtils {
    private final static Logger LOG = LoggerFactory.getLogger(SerializationUtils.class);
    private final static ObjectMapper objectMapper = new ObjectMapper();

    static {
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    }

    static <T> byte[] serializeObject(T object) {
        try {
            return objectMapper.writeValueAsString(object).getBytes();
        } catch (JsonProcessingException e) {
            LOG.error("Serialization error:" + e.getMessage());
        }
        return new byte[0];
    }

    public static <T> Mono<T> deserializeAuthentication(byte[] authentication, Class<T> tClass) {
        return Mono.fromCallable(() -> objectMapper.readValue(authentication, tClass))
                .doOnError(t -> {throw Exceptions.propagate(t);});
    }
}
