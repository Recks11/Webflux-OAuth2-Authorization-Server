package dev.rexijie.oauth.oauth2server.config;

import dev.rexijie.oauth.oauth2server.auth.ClientDetailsRepositoryReactiveAuthenticationManager;
import dev.rexijie.oauth.oauth2server.repository.ClientRepository;
import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.services.DefaultClientDetailsService;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class WebSecurityConfig {

    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(UserRepository userRepository,
                             ClientRepository clientRepository,
                             PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.clientRepository = clientRepository;
    }

    @Bean
    public SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange()
                                .authenticated()
                )
                .authenticationManager(clientAuthenticationManager())
                .httpBasic(withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable);
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
                ).authenticationManager(userAuthenticationManager())
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean @Primary
    public ReactiveAuthenticationManager clientAuthenticationManager() {
        var manager = new ClientDetailsRepositoryReactiveAuthenticationManager(
                new DefaultClientDetailsService(clientRepository, passwordEncoder)
        );
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }

    @Bean
    public ReactiveAuthenticationManager userAuthenticationManager() {
        var manager = new UserDetailsRepositoryReactiveAuthenticationManager(
                new DefaultReactiveUserDetailsService(userRepository)
        );
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }
}
