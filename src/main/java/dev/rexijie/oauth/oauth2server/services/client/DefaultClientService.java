package dev.rexijie.oauth.oauth2server.services.client;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.error.ApiError;
import dev.rexijie.oauth.oauth2server.generators.CredentialsGenerator;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

// TODO (Add Validation)
@Service
public class DefaultClientService implements ClientService {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultClientService.class);
    private final ClientRepository clientRepository;
    private final CredentialsGenerator<ClientCredentials> credentialsGenerator;
    private final PasswordEncoder encoder;

    public DefaultClientService(ClientRepository clientRepository,
                                CredentialsGenerator<ClientCredentials> credentialsGenerator,
                                PasswordEncoder encoder) {
        this.clientRepository = clientRepository;
        this.credentialsGenerator = credentialsGenerator;
        this.encoder = encoder;
    }


    @Override
    public Mono<ClientCredentials> createClient(ClientDTO clientDTO) {
        return Mono.just(clientDTO)
                .doOnNext(this::validateClient)
                .zipWith(Mono.fromCallable(credentialsGenerator::generateCredentials))
                .flatMap(tuple -> {
                    var dto = tuple.getT1();
                    var credentials = tuple.getT2();
                    var client = ClientDTO.ClientMapper
                            .toClient(dto,
                                    encoder.encode(credentials.clientId()),
                                    encoder.encode(credentials.clientSecret()));
                    return clientRepository.save(client)
                            .thenReturn(credentials);
                }).doOnError(throwable -> {
                    throw Exceptions.propagate(throwable);
                })
                .doOnSuccess(credentials -> LOG.debug("Created Client: Client [id: {}, secret: [HIDDEN]]", credentials.clientId()));

    }

    @Override
    public Mono<ClientDTO> findClientById(String credentials) {
        return clientRepository.findByClientId(credentials)
                .switchIfEmpty(Mono.error(new ApiError(404, "Client does not exist")))
                .map(ClientDTO.ClientMapper::toDto)
                .doOnSuccess(clientDTO -> LOG.debug("found client with id {}", credentials));
    }

    @Override
    public Mono<ClientDTO> findClientWithCredentials(ClientCredentials credentials) {
        return clientRepository.findByClientIdAndClientSecret(credentials.clientId(), credentials.clientSecret())
                .switchIfEmpty(Mono.error(new ApiError(404, "Client does not exist")))
                .map(ClientDTO.ClientMapper::toDto)
                .doOnSuccess(clientDTO -> LOG.debug("found client with id {} and a secret", credentials.clientId()));
    }

    private Mono<Void> validateClient(ClientDTO clientDTO) {
        return Mono.just(clientDTO).then()
                .doOnSuccess(clientDTO1 -> LOG.debug("validated client named {}", clientDTO.getClientName()));
    }
}
