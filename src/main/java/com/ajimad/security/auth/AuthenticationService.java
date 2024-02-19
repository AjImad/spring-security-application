package com.ajimad.security.auth;

import com.ajimad.security.config.JwtService;
import com.ajimad.security.user.Role;
import com.ajimad.security.user.User;
import com.ajimad.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    // Since we need to connect to database we need UserRepository
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    // This method allow us to create new user and save it in DB and return the generated token out of it.
    public AuthenticationResponse register(RegisterRequest request) {
        // building the user object
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user); // save the user in the database
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        return null;
    }
}
