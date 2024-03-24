package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.auth.AuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.auth.EncryptedCodeAuthorizationCodeWrapper;
import dev.rexijie.oauth.oauth2server.error.OAuthError;
import dev.rexijie.oauth.oauth2server.generators.SecretGenerator;
import dev.rexijie.oauth.oauth2server.repository.AuthorizationCodeRepository;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.services.token.TokenServices;
import dev.rexijie.oauth.oauth2server.token.OAuth2Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static dev.rexijie.oauth.oauth2server.api.domain.ApiVars.CLIENT_AUTHENTICATION_METHOD;

/**
 * Authorization code services that creates and consumes authorization codes for the
 * autorization_code flow.
 */
@Component
public class DefaultReactiveAuthorizationCodeServices implements ReactiveAuthorizationCodeServices {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultReactiveAuthorizationCodeServices.class);
    private static final String TOKEN_SEPARATOR = "&/";
//    private static final String TOKEN_HASH = "t_hash";
//    private static final String TOKEN_HASH_SEPARATOR = ":";
    private static final String TOKEN_PREFIX = "tk";
    private final ClientService clientService;
    private final TokenService tokenService;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final SecretGenerator secretGenerator;
    private final TokenServices tokenServices;

    public DefaultReactiveAuthorizationCodeServices(ClientService clientService,
                                                    @Qualifier("authorizationCodeTokenService") TokenService tokenService,
                                                    AuthorizationCodeRepository authorizationCodeRepository,
                                                    SecretGenerator secretGenerator,
                                                    TokenServices tokenServices) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.secretGenerator = secretGenerator;
        this.tokenServices = tokenServices;
    }

    // TODO(When code is used more than once, then revoke all tokens generated by that code)
    // TODO(Rework: new process will generate a jwt approval token and load it for scope approval)
    // this token will be stored in the session. this prevents serialization of the authentication object.
    @Override
    public Mono<AuthorizationCodeWrapper> createAuthorizationCode(Authentication authentication) {
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {
            return clientService.findClientById(oAuth2Authentication.getPrincipal().toString())
                    .doOnNext(clientDTO -> {
                        Optional<String> redirect = clientDTO.getRedirectUris().stream().findFirst();
                        if (redirect.isEmpty())
                            throw Exceptions.propagate(new OAuthError(OAuthError.OAuthErrors.INVALID_CLIENT));
                    })
                    .flatMap(c -> {
                        oAuth2Authentication.setDetails(c);
                        oAuth2Authentication.getStoredRequest().setAttribute(CLIENT_AUTHENTICATION_METHOD,
                                c.getTokenEndpointAuthenticationMethod());
                        return tokenServices.createAccessToken(oAuth2Authentication);
                    })
                    .flatMap(auth2Token -> {
                        Token token = tokenService.allocateToken(createAdditionalInformation(auth2Token.getTokenValue()));
                        String code = secretGenerator.generate(16);
                        AuthorizationCodeWrapper wrapper = new EncryptedCodeAuthorizationCodeWrapper(
                                code,
                                token.getKey().getBytes(StandardCharsets.UTF_8)
                        );
                        return authorizationCodeRepository.save(wrapper);
                    });
        }
        return Mono.error(new OAuthError(OAuthError.OAuthErrors.UNAUTHORIZED_CLIENT, "invalid client authentication"));
    }

    @Override
    public Mono<OAuth2Authentication> consumeAuthorizationCode(String code, Authentication authentication) {
        return authorizationCodeRepository.findByCode(code)
                .doOnNext(authorizationCodeWrapper ->
                        LOG.info("found authentication with code {}", authorizationCodeWrapper.getCode()))
                .flatMap(wrapper -> {
                    Token token = tokenService.verifyToken(new String(wrapper.getAuthentication()));
                    var tuple = convertAdditionalInformation(token.getExtendedInformation());
                    String tokenValue = tuple[0].toString();
                    return tokenServices.readAuthentication(() -> tokenValue, (OAuth2Authentication) authentication);
                }).doOnSuccess(auth -> LOG.info("successfully consumed authorization code"));
    }

    public String createAdditionalInformation(String tokenValue) {
        return TOKEN_PREFIX + TOKEN_SEPARATOR + tokenValue;
    }

    public Object[] convertAdditionalInformation(String additionalInformation) {
        String token = additionalInformation.split(TOKEN_SEPARATOR)[1];
        return new Object[]{token, ""};
    }
}