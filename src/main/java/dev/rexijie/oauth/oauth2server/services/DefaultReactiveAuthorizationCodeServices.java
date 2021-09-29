package dev.rexijie.oauth.oauth2server.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rexijie.oauth.oauth2server.auth.AuthenticationSerializationWrapper;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.token.OAuth2ApprovalAuthorizationToken;
import dev.rexijie.oauth.oauth2server.util.SerializationUtils;
import org.bson.internal.Base64;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

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
                .map(wrapper -> {
                    Token token = tokenService.verifyToken(wrapper.getApprovalToken());
                    return convertAdditionalInformation(token.getExtendedInformation());
                });
    }

    public String createAdditionalInformation(OAuth2ApprovalAuthorizationToken token) {
        final StringBuilder sb = new StringBuilder();
        sb.append(token.getPrincipal()).append(SPLIT_TOKEN)
                .append(token.getAuthorizedClientId()).append(SPLIT_TOKEN)
                .append(token.isAllApproved()).append(TOKEN_END);

        for (String scope : token.getApprovedScopes()) {
            sb.append(scope).append(SCOPE_SPLIT);
        }

        return sb.toString();
    }

    public OAuth2ApprovalAuthorizationToken convertAdditionalInformation(String additionalInformation) {
        String[] split = additionalInformation.split(SPLIT_TOKEN);
        String principal = split[0];
        String clientId = split[1];
        boolean allApproved = Boolean.parseBoolean(split[2]);
        String scopesExpression = split[4];
        String[] scopeTokens = scopesExpression.split(SCOPE_SPLIT);
        Set<String> approvedScopes = new HashSet<>(Arrays.asList(scopeTokens));
        return new OAuth2ApprovalAuthorizationToken(
                principal, null, clientId, approvedScopes
        );
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
