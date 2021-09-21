package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.error.ApiError;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

// TODO (Add Validation)
@Service
public class DefaultClientService implements ClientService {
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
        return validateClient(clientDTO)
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
                });

    }

    @Override
    public Mono<ClientDTO> findClientById(String credentials) {
        return clientRepository.findByClientId(credentials)
                .switchIfEmpty(Mono.error(new ApiError(404, "Client does not exist")))
                .map(ClientDTO.ClientMapper::toDto);
    }

    @Override
    public Mono<ClientDTO> findClientByWithCredentials(ClientCredentials credentials) {
        return clientRepository.findByClientIdAndClientSecret(credentials.clientId(), credentials.clientSecret())
                .switchIfEmpty(Mono.error(new ApiError(404, "Client does not exist")))
                .map(ClientDTO.ClientMapper::toDto);
    }

    private Mono<ClientDTO> validateClient(ClientDTO clientDTO) {
        return Mono.just(clientDTO);
    }
}
