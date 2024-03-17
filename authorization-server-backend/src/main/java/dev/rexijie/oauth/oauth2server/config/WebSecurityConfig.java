package dev.rexijie.oauth.oauth2server.config;

import dev.rexijie.oauth.oauth2server.auth.AuthenticationServerAuthenticationConverter;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveClientAuthenticationManager;
import dev.rexijie.oauth.oauth2server.auth.manager.ReactiveUserAuthenticationManager;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.services.client.DefaultClientDetailsService;
import dev.rexijie.oauth.oauth2server.services.user.DefaultReactiveUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class WebSecurityConfig {

    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2Properties oAuth2Properties;

    public WebSecurityConfig(UserRepository userRepository,
                             ClientRepository clientRepository,
                             PasswordEncoder passwordEncoder,
                             OAuth2Properties oAuth2Properties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.clientRepository = clientRepository;
        this.oAuth2Properties = oAuth2Properties;
    }

    @Bean
    public SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
        // TODO configure auth entrypoint
        http
                .logout().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .csrf().disable();
        http
                .securityMatcher(new PathPatternParserServerWebExchangeMatcher("%s/**".
                        formatted(oAuth2Properties.server().basePath().toLowerCase())))
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange()
                                .authenticated()
                ).authenticationManager(clientAuthenticationManager())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        var authWebFilter = new AuthenticationWebFilter(clientAuthenticationManager());
        authWebFilter.setServerAuthenticationConverter(new AuthenticationServerAuthenticationConverter());
        authWebFilter.setAuthenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("/login"));

        http.addFilterAt(authWebFilter, SecurityWebFiltersOrder.HTTP_BASIC);
        return http.build();
    }

    @Bean
    public SecurityWebFilterChain tokenHttpSecurity(ServerHttpSecurity http) {
        http
                .securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange()
                                .authenticated()
                ).authenticationManager(clientAuthenticationManager())
                .csrf().disable()
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    @Primary
    public ReactiveAuthenticationManager clientAuthenticationManager() {
        var manager = new ReactiveClientAuthenticationManager(
                new DefaultClientDetailsService(clientRepository, passwordEncoder)
        );
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }

    @Bean
    public ReactiveAuthenticationManager userAuthenticationManager() {
        var manager = new ReactiveUserAuthenticationManager(
                new DefaultReactiveUserDetailsService(userRepository)
        );
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }
}
