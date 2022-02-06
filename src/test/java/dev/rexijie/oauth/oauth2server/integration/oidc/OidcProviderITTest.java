package dev.rexijie.oauth.oauth2server.integration.oidc;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderEndpointMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import dev.rexijie.oauth.oauth2server.api.OAuthTest;
import dev.rexijie.oauth.oauth2server.api.constants.Endpoints;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class OidcProviderITTest extends OAuthTest {

    @Override
    public void setUp() {

    }

    @Test
    void oidcConfiguration() {
        apiClient()
                .get()
                .uri(URI.create(Endpoints.OIDC_BASE + "/.well-known/openid-configuration"))
                .exchange()
                .expectBody(String.class)
                .consumeWith(res -> {
                    try {
                        OIDCProviderMetadata parse = OIDCProviderMetadata.parse(res.getResponseBody());
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                });
    }
}
