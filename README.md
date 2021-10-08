# Webflux OAuth2 Authorization Server
This is an OAuth2 authorization server written with Spring Boot capable of generating and granting JWTs. built with SpringWebflux


## Endpoints
The baseUrl is `http://127.0.0.1:8080/**`. but you should provide yours using the `${SERVER_URL}` environment variable.

There are 8 endpoints
- `/oauth/token` to get tokens with the password, implicit, client_credentials and refresh_token flows.
- `/oauth/authorize` for the authorization_code flow.
- `/oauth/check_token` to check the tokens with your resource server.
- `/oauth/token_key` to get the public key used to verify tokens.
- `/oauth/introspect` the introspection endpoint
- `/openid/userinfo` user info endpoint
- `/openid/.well-known/jwks.json` openid jwks_uri 
- `/openid/.well-known/openid-configuration` openid discovery endpoint


## USAGE
This authorization server supports openid discovery which enables it take advantage of spring-security-oauth2 openid configuration

### Using with a RESOURCE SERVER
Configuring a resource server app to use this authorization server is as easy as setting the issuer-uri property in the application.properties or application.yml file
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://127.0.0.1:8080/openid
```
You can then configure security in your WebSecurityConfigurerAdapter class. the Jwt decoder Bean gets its configuration from the authorization server.


```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Override
    protected void configure(HttpSecurity http) {
        http
                .authorizeRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                                .decoder(jwtDecoder()))
                );
    }

    JwtAuthenticationConverter jwtAuthenticationConverter() {
        CustomAuthenticationConverter grantedAuthoritiesConverter = new CustomAuthenticationConverter();
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }
}
```
The `jwtAuthenticationConverter()` is optional, but you can add it if you want to customise the granted authorities in the generated jwt.

### Using with a CLIENT
configuring a `Spring-security-oauth2-client` to use the authorization server you need to provide the issuer-uri property. 
```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          rexijie-dev:
            issuerUri: http://127.0.0.1:8080/openid
```
and then the security configuration
```java
@EnableWebFluxSecurity
public class OAuth2Config {

    // The Authorization Server URI.
    @Value("${spring.security.oauth2.client.provider.rexijie-dev.issuerUri}")
    private String issuerUri;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(
                        authorize -> authorize
                                .pathMatchers("/").permitAll()
                                .anyExchange().authenticated()
                )
                .oauth2Client(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }
}
```
## FLOWS
This section describes how to use the various OAuth2 flows.

JWTs produced by this application are encrypted using the RSA256 algorithm and hence are signed with a key pair. The public key can be gotten from the `/oauth/token_key` endpoint.

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXhpamllQGdtYWlsLmNvbSIsInJvbGUiOiJVU0VSIiwic2NvcGUiOlsicmVhZCJdLCJpc3MiOiJodHRwczovL3JleGlqaWUuZGV2IiwiZXhwIjoxNTk4MDE0NTcyLCJhdXRob3JpdGllcyI6WyJST0xFX0NBTl9WSUVXIiwiUk9MRV9VU0VSIl0sImp0aSI6IjViMzA1YTE4LWQ0NWMtNDA4YS1iNGU3LWEzYmYwODQ3NWE4ZCIsImNsaWVudF9pZCI6Im1hbmFnZW1lbnQtYXBwIn0.li0f2gEA2VsbginzWa0ELcKrWGXeXSybsZVFdQiWHRZ2YbqvuYbpr0ReN_D6_0zWgCBdWjblibSLUiLrM2vlQBr0UarU1RnaDP5WDTxnTBch80rjWIfc-_QBwFOuitD7iXHwRhJLDObv491YcxLcmXhJmPTr-CavgG-cruD6kuqIzqpwQ22-TXZ_iHT2OCddsSX-DUtXMIb7oBIkbUgdc3UCmFn2fdVsFxZbUM2CYsKc56VgGO27MlfKfRQhCfIhBIzpvXmBRUETWMipOJOCtJ60JPW1NM78-lgV-Y8lw280SZAgK5jukJNshNXJgkqw42scQMSdXJTKg-WBWoV6Bg",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXhpamllQGdtYWlsLmNvbSIsInJvbGUiOiJVU0VSIiwic2NvcGUiOlsicmVhZCJdLCJhdGkiOiI1YjMwNWExOC1kNDVjLTQwOGEtYjRlNy1hM2JmMDg0NzVhOGQiLCJpc3MiOiJodHRwczovL3JleGlqaWUuZGV2IiwiZXhwIjoxNjAwNTYzMzcyLCJhdXRob3JpdGllcyI6WyJST0xFX0NBTl9WSUVXIiwiUk9MRV9VU0VSIl0sImp0aSI6IjE1YmNjYjQwLTQ3NWEtNDk4My05YWI2LTczNmZhNmI2MDU5OSIsImNsaWVudF9pZCI6Im1hbmFnZW1lbnQtYXBwIn0.P8tW6DsEd1qefdWMGZiBq7hlaYSl6hFZ2aRACHf5u-F-NUTY7F9wiB1vXRoDFS577AwRAajPFB5Mq-IFsGl4LfOoth9AjJJpA9EF3hPXj6XH6f49Ozzn2mF8AvEZBO-SJ04eK1eS-cJN03YK4FBTO9LT59-6SLqzhGE8x-NwGQWSab91Gv7_DmmuPHEM_vAnQfBV9ycuN0wdcJmaj1wsRnbBAtCe-bETu9LZgQ5vw5ANCd8Dfz0DTM2vu6vCFTpFeFwMy91Ol73POh34z_pGd2tgSaWzJm_qCVq-hKOjXj-4d2tmDvLcwUzPtwCvbUrbPoQYyF9RZEO8NOdr0--3IA",
    "expires_in": 43199,
    "scope": "read",
    "jti": "5b305a18-d45c-408a-b4e7-a3bf08475a8d"
}
```
### PASSWORD FLOW
...
### IMPLICIT FLOW \[Deprecated\]
...
### CLIENT CREDENTIALS FLOW
...
### REFRESH TOKEN FLOW
...
### AUTHORIZATION CODE FLOW
...

