package dev.rexijie.oauth.oauth2server.config;

import dev.rexijie.oauth.oauth2server.repository.UserRepository;
import dev.rexijie.oauth.oauth2server.services.DefaultReactiveUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges ->
                        exchanges
                                .anyExchange()
                                .authenticated()
                )
                .httpBasic(withDefaults());
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
                ).authenticationManager(actualUserAuthenticationManager())
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public ReactiveAuthenticationManager actualUserAuthenticationManager() {
        var manager = new UserDetailsRepositoryReactiveAuthenticationManager(
                new DefaultReactiveUserDetailsService(userRepository)
        );
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }
}
