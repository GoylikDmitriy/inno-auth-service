package com.goylik.auth_service.service.impl;

import com.goylik.auth_service.exception.CredentialsAlreadyExistException;
import com.goylik.auth_service.exception.EmailAlreadyExistsException;
import com.goylik.auth_service.exception.InvalidTokenException;
import com.goylik.auth_service.exception.UserNotFoundException;
import com.goylik.auth_service.model.dto.request.LoginRequest;
import com.goylik.auth_service.model.dto.request.RefreshTokenRequest;
import com.goylik.auth_service.model.dto.request.SaveCredentialsRequest;
import com.goylik.auth_service.model.dto.request.ValidateTokenRequest;
import com.goylik.auth_service.model.dto.response.TokenResponse;
import com.goylik.auth_service.model.dto.response.TokenValidationResponse;
import com.goylik.auth_service.model.entity.UserCredentials;
import com.goylik.auth_service.model.enums.Role;
import com.goylik.auth_service.repository.UserCredentialsRepository;
import com.goylik.auth_service.security.jwt.JwtService;
import com.goylik.auth_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        var credentials = fetchUserCredentialsByEmailOrThrow(request.email());

        return buildTokenResponse(credentials.getUserId(), credentials.getRole());
    }

    private UserCredentials fetchUserCredentialsByEmailOrThrow(String email) {
        return userCredentialsRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not registered with email: " + email));
    }

    private TokenResponse buildTokenResponse(Long userId, Role role) {
        return new TokenResponse(
                jwtService.generateAccessToken(userId, role),
                jwtService.generateRefreshToken(userId, role)
        );
    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        TokenValidationResponse validation = jwtService.extractAll(request.refreshToken());
        if (!validation.valid()) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        return buildTokenResponse(validation.userId(), validation.role());
    }

    @Override
    public TokenValidationResponse validateToken(ValidateTokenRequest request) {
        return jwtService.extractAll(request.token());
    }

    @Override
    @Transactional
    public void saveCredentials(SaveCredentialsRequest request) {
        if (userCredentialsRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException("Email already taken: " + request.email());
        }

        if (userCredentialsRepository.existsByUserId(request.userId())) {
            throw new CredentialsAlreadyExistException("Credentials already exist for userId: " + request.userId());
        }

        var credentials = buildUserCredentials(request);
        userCredentialsRepository.save(credentials);
    }

    private UserCredentials buildUserCredentials(SaveCredentialsRequest request) {
        var credentials = new UserCredentials();
        credentials.setUserId(request.userId());
        credentials.setEmail(request.email());
        credentials.setPassword(passwordEncoder.encode(request.password()));
        credentials.setRole(request.role());
        credentials.setActive(true);

        return credentials;
    }
}
