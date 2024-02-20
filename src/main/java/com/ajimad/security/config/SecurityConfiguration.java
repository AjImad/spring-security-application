package com.ajimad.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //
@RequiredArgsConstructor
public class SecurityConfiguration {
    // We create this configuration class to use the JwtAuthenticationFilter to intercept every http request

    // At the application startup, Spring Security will look for Bean of type security filter chain.
    // The security filter chain bean is responsible for configuring all the HTTP security of our application.
    // So we need to create this Bean

    private final JwtAuthenticationFilter jwtAuthFilter;
    // NOTE: AuthenticationProvider bean defined in ApplicationConfig file
    private final AuthenticationProvider authenticationProvider;


    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // The authentication provider is responsible for verifying the user credentials and creating Authentication object
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
        // the configured HttpSecurity is built into a SecurityFilterChain and returned. This SecurityFilterChain
        // is what spring security use to apply the security configuration.
    }

}
