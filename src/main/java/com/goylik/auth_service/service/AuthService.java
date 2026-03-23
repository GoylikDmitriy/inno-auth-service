package com.goylik.auth_service.service;

import com.goylik.auth_service.model.dto.request.LoginRequest;
import com.goylik.auth_service.model.dto.request.RefreshTokenRequest;
import com.goylik.auth_service.model.dto.request.SaveCredentialsRequest;
import com.goylik.auth_service.model.dto.request.ValidateTokenRequest;
import com.goylik.auth_service.model.dto.response.TokenResponse;
import com.goylik.auth_service.model.dto.response.TokenValidationResponse;

public interface AuthService {
    TokenResponse login(LoginRequest request);
    TokenResponse refreshToken(RefreshTokenRequest request);
    TokenValidationResponse validateToken(ValidateTokenRequest request);
    void saveCredentials(SaveCredentialsRequest request);
}
