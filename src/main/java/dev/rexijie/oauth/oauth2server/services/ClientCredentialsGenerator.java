package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import org.springframework.stereotype.Component;

@Component
public class ClientCredentialsGenerator implements CredentialsGenerator<ClientCredentials> {

    private final SecretGenerator secretGenerator;

    public ClientCredentialsGenerator(SecretGenerator secretGenerator) {
        this.secretGenerator = secretGenerator;
    }

    @Override
    public ClientCredentials generateCredentials() {
        return new ClientCredentials(
                secretGenerator.generate(8),
                secretGenerator.generate(16)
        );
    }
}
