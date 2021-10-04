package dev.rexijie.oauth.oauth2server.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationSerializationWrapper;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import org.bson.internal.Base64;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.*;

import static dev.rexijie.oauth.oauth2server.util.SerializationUtils.deserializeAuthentication;

/**
 * Authorization code services that creates and consumes authorization codes for the
 * autorization_code flow.
 */
@Component
public class DefaultReactiveAuthorizationCodeServices implements ReactiveAuthorizationCodeServices {
    private static final String SPLIT_TOKEN = "&/";
    private static final String TOKEN_END = ";";
    private static final String SCOPE_SPLIT = "&";
    private final ClientService clientService;
    private final TokenService tokenService;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final ObjectMapper objectMapper;

    public DefaultReactiveAuthorizationCodeServices(ClientService clientService,
                                                    @Qualifier("authorizationCodeTokenServices") TokenService tokenService,
                                                    AuthorizationCodeRepository authorizationCodeRepository,
                                                    ObjectMapper objectMapper) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.objectMapper = objectMapper;
    }

    // Algorithm: find client, get redirection, if approved set redirection uri and generate text
    // store text as key and return redirect
    // TODO(make this work)
    @Override
    public Mono<OAuth2ApprovalAuthorizationToken> createAuthorizationCode(Authentication authentication) {
        OAuth2ApprovalAuthorizationToken appAuthToken = (OAuth2ApprovalAuthorizationToken) authentication;
        return clientService.findClientById(appAuthToken.getAuthorizedClientId())
                .map(client -> {
                    appAuthToken.setDetails(client);
                    Optional<String> redirect = client.getRedirectUris().stream().findFirst();
                    if (redirect.isEmpty())
                        throw Exceptions.propagate(new OAuthError(OAuthError.OAuthErrors.INVALID_CLIENT));
                    return tokenService.allocateToken(createAdditionalInformation(appAuthToken));
                }).flatMap(token -> writeToByteArray(appAuthToken)
                        .flatMap(bytes -> {
                            String code = Base64.encode(Arrays.copyOfRange(bytes, 0, 24));
                            appAuthToken.setApprovalTokenId(code);

                            var wrapper = new AuthenticationSerializationWrapper(
                                    code,
                                    token.getKey(), bytes);
                            return authorizationCodeRepository
                                    .save(wrapper)
                                    .map(serializedAuth -> {
                                        appAuthToken.setApprovalTokenId(serializedAuth.getCode());
                                        return appAuthToken;
                                    });
                        }));
    }

    @Override
    public Mono<OAuth2ApprovalAuthorizationToken> consumeAuthorizationCode(String code) {
        return authorizationCodeRepository.findByCode(code)
                .flatMap(wrapper -> {
                    Token token = tokenService.verifyToken(wrapper.getApprovalToken());
                    var tuple = convertAdditionalInformation(token.getExtendedInformation());
                    return deserializeAuthentication(wrapper.getAuthentication(), OAuth2ApprovalAuthorizationToken.class)
                            .map(storedAuth -> verifyAuth(storedAuth, tuple));
                });
    }

    private OAuth2ApprovalAuthorizationToken verifyAuth(OAuth2ApprovalAuthorizationToken storedAuth,
                                                        Object[] tuple) {
        var token = (OAuth2ApprovalAuthorizationToken) tuple[0];
        Objects.requireNonNull(tuple[1], "invalid token");
        var h = Integer.parseInt(tuple[1].toString());
        if (storedAuth.hashCode() != h)
            throw new OAuthError(null, 401, "M2X3", "the request is invalid");
        if (storedAuth.getApprovedScopes().equals(token.getApprovedScopes()) &&
                storedAuth.getPrincipal().equals(token.getPrincipal()) &&
                storedAuth.getAuthorizedClientId().equals(token.getAuthorizedClientId()) &&
                storedAuth.getApprovalMap().equals(token.getApprovalMap())) {
            token.setDetails(storedAuth.getDetails());
            token.setAuthenticated(storedAuth.isAuthenticated());
            token.setAuthorizationRequest(storedAuth.getAuthorizationRequest());
            token.setApprovalTokenId(storedAuth.getApprovalTokenId());
        }
        return token;
    }

    public String createAdditionalInformation(OAuth2ApprovalAuthorizationToken token) {
        final StringBuilder sb = new StringBuilder();
        sb.append(token.getPrincipal()).append(SPLIT_TOKEN)
                .append(token.getAuthorizedClientId()).append(SPLIT_TOKEN)
                .append(token.isAllApproved()).append(SPLIT_TOKEN);

        for (String scope : token.getApprovedScopes()) {
            sb.append(scope).append(SCOPE_SPLIT);
        }
        sb.append(SPLIT_TOKEN).append("t_hash:").append(token.hashCode());

        return sb.toString();
    }

    public Object[] convertAdditionalInformation(String additionalInformation) {
        String[] split = additionalInformation.split(SPLIT_TOKEN);
        String principal = split[0];
        String clientId = split[1];
        String scopesExpression = split[3];
        String hash = split[4];
        String[] scopeTokens = scopesExpression.split(SCOPE_SPLIT);
        Set<String> approvedScopes = new HashSet<>(Arrays.asList(scopeTokens));

        OAuth2ApprovalAuthorizationToken token = new OAuth2ApprovalAuthorizationToken(
                principal, null, clientId, approvedScopes
        );

        for (String scope : approvedScopes)
            token.approve(scope);

        return new Object[]{token, hash.split(":")[1]};
    }

    public Mono<byte[]> writeToByteArray(Object object) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsBytes(object))
                .doOnError(throwable -> {
                    throw Exceptions.propagate(throwable);
                });
    }

    private String encode(byte[] arr, String salt) {
        return Base64.encode(arr);
    }
}
