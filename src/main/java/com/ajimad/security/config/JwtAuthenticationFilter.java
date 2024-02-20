package com.ajimad.security.config;

import com.ajimad.security.token.Token;
import com.ajimad.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.swing.text.html.Option;
import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor //
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // JwtAuthenticationFilter act as an entry point for securing your application with JWT-Based authentication,
    // allowing only request with valid token to proceed and access protected resources.

    // this custom filter is basically used to intercept request, extract JWT validate it, and set the authentication
    // in the security context.

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if ( authHeader == null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt); // extracting the userEmail from JWT token
        // Entering this condition it's mean the user not yet authenticated: not yet successfully
        // proven their identity through the established authentication process
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // Load the actual user from the database by username (userEmail)
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Check if the generated user token that is stored in Token table is not expired or revoked
            boolean isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);

            // Check if the JWT is a valid token
            if(jwtService.isTokenValid(jwt, userDetails) && isTokenValid){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // After checking the JWT validation, we need to pass the hand to the next filters to be executed
        filterChain.doFilter(request, response);
    }
}
