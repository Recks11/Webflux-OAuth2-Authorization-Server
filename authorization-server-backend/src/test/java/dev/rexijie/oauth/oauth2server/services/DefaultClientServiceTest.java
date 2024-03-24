package dev.rexijie.oauth.oauth2server.services;

import dev.rexijie.oauth.oauth2server.api.domain.ClientCredentials;
import dev.rexijie.oauth.oauth2server.generators.CredentialsGenerator;
import dev.rexijie.oauth.oauth2server.model.Client;
import dev.rexijie.oauth.oauth2server.model.dto.ClientDTO;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.services.client.ClientService;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static dev.rexijie.oauth.oauth2server.mocks.ModelMocks.testClient;
import static dev.rexijie.oauth.oauth2server.model.dto.ClientDTO.ClientMapper.toDto;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
//@WebFluxTest
class DefaultClientServiceTest {

    private ClientService defaultClientService;
    @MockBean
    private ClientRepository clientRepository;
    @MockBean
    private CredentialsGenerator<ClientCredentials> credentialsGenerator;
    @MockBean
    private PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        defaultClientService = new DefaultClientService(
                clientRepository,
                credentialsGenerator,
                encoder
        );
    }

    @AfterEach
    void afterTest() {
        clearInvocations(clientRepository,
                credentialsGenerator,
                encoder);
    }

    @Test
    void whenCreateClient_generateCreds_andSuccess() {
        var genCred = new ClientCredentials("gen_id", "gen_secret");
        when(clientRepository.save(any(Client.class)))
                .thenReturn(Mono.just(testClient()));
        when(encoder.encode(any(String.class)))
                .thenReturn("encoded_string");
        when(credentialsGenerator.generateCredentials())
                .thenReturn(genCred);

        Mono<ClientCredentials> client = defaultClientService.createClient(new ClientDTO());

        StepVerifier.create(client)
                .expectNext(genCred)
                .verifyComplete();

        verify(clientRepository, times(1))
                .save(any(Client.class));
        verify(credentialsGenerator, times(1))
                .generateCredentials();
        verify(encoder, atLeast(1))
                .encode(any(String.class));
    }

    @Test
    void findClientById() {
        var clientMock = testClient();
        when(clientRepository.findByClientId(any(String.class)))
                .thenReturn(Mono.just(clientMock));

        Mono<ClientDTO> gen_client = defaultClientService.findClientById("gen_client");

        StepVerifier.create(gen_client)
                .expectNextMatches(clientDTO -> clientDTO.equals(
                        toDto(clientMock)
                ))
                .expectComplete()
                .verify();

    }

    @Test
    void findClientByWithCredentials() {
    }
}