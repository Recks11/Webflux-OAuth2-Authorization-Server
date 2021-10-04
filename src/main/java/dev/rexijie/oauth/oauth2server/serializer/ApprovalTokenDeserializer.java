package dev.rexijie.oauth.oauth2server.serializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.rexijie.oauth.oauth2server.api.domain.AuthorizationRequest;
import dev.rexijie.oauth.oauth2server.model.User;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;

import java.io.IOException;
import java.util.Map;

public class ApprovalTokenDeserializer extends StdDeserializer<OAuth2ApprovalAuthorizationToken> {

    private final ObjectMapper objectMapper = new JsonMapper();

    public ApprovalTokenDeserializer() {
        this(null);
    }

    public ApprovalTokenDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public OAuth2ApprovalAuthorizationToken deserialize(JsonParser parser, DeserializationContext context) throws IOException {

        JsonNode node = parser.getCodec().readTree(parser);
        var credentials = node.get("credentials").asText();
        var principal = node.get("principal").asText();
        var approvalTokenId = node.get("approvalTokenId").asText();
        var authReq = node.get("authorizationRequest").toString();
        var aM = objectMapper.readValue(
                node.get("approvalMap").toString(), new TypeReference<Map<String, Boolean>>() {
                });
        var authorizationRequest = objectMapper.readValue(authReq, AuthorizationRequest.class);
        var details = node.get("details");
        var authenticated = node.get("authenticated").asBoolean();

        var auth = new OAuth2ApprovalAuthorizationToken(
                principal,
                credentials,
                authorizationRequest
        );
        auth.setAuthenticated(authenticated);
        auth.setApprovalTokenId(approvalTokenId);
        aM.keySet().stream()
                .filter(aM::get)
                .forEach(auth::approve);
        if (!details.isNull() && !details.isEmpty()) {
            var clientDetails = resolveDetails((ObjectNode) details, ClientDTO.class, User.class);
            auth.setDetails(clientDetails);
        }
        return auth;
    }

    private Object resolveDetails(ObjectNode object, Class<?> type1, Class<?> fallback) {
        Object details;
        try {
            details = objectMapper.readValue(object.toString(), type1);
        } catch (Exception ex) {
            if (fallback == null) throw new RuntimeException(ex);
            details = resolveDetails(object, fallback, null);
        }
        return details;
    }
}
