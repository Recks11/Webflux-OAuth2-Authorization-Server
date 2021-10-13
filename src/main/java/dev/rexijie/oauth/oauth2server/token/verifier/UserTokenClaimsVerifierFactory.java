package dev.rexijie.oauth.oauth2server.token.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetailsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class UserTokenClaimsVerifierFactory {

    public UserTokenClaimsVerifierFactory() {

    }

    public JWTClaimsSetVerifier<?> getVerifier(String audience,
                                               String issuer) {
        var acceptedAudience = new HashSet<>(Set.of(audience));
        var requiredClaims = Set.of(ClaimsSet.AUD_CLAIM_NAME, ClaimsSet.ISS_CLAIM_NAME);
        return new DefaultJWTClaimsVerifier<>(
                acceptedAudience,
                claimSetWith()
                        .audience(audience)
                        .issuer(issuer)
                        .build(),
                requiredClaims,
                null
        );
    }

    public JWTClaimsSetVerifier<?> getJWTAssertionDetailsVerifier(Set<String> audience) {
        var audienceSet = audience.stream().map(Audience::new)
                .collect(Collectors.toSet());
        return new JWTAssertionDetailsVerifier(audienceSet);
    }

    private JWTClaimsSet.Builder claimSetWith() {
        return new JWTClaimsSet.Builder();
    }
}
