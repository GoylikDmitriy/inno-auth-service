package com.goylik.auth_service.controller;

import com.goylik.auth_service.model.dto.request.LoginRequest;
import com.goylik.auth_service.model.dto.request.RefreshTokenRequest;
import com.goylik.auth_service.model.dto.request.SaveCredentialsRequest;
import com.goylik.auth_service.model.dto.request.ValidateTokenRequest;
import com.goylik.auth_service.model.dto.response.TokenResponse;
import com.goylik.auth_service.model.dto.response.TokenValidationResponse;
import com.goylik.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/save-credentials")
    @ResponseStatus(HttpStatus.CREATED)
    public void saveCredentials(@Valid @RequestBody SaveCredentialsRequest request) {
        authService.saveCredentials(request);
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/validate")
    public TokenValidationResponse validateToken(@Valid @RequestBody ValidateTokenRequest request) {
        return authService.validateToken(request);
    }

    @PostMapping("/refresh")
    public TokenResponse refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request);
    }
}
