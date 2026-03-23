package com.goylik.auth_service.security.jwt;

import com.goylik.auth_service.model.dto.response.TokenValidationResponse;
import com.goylik.auth_service.model.enums.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Value("${app.jwt.clock-skew-seconds:30}")
    private long clockSkewSeconds;

    public String generateAccessToken(Long userId, Role role) {
        return buildToken(userId, role, accessTokenExpirationMs);
    }

    public String generateRefreshToken(Long userId, Role role) {
        return buildToken(userId, role, refreshTokenExpirationMs);
    }

    private String buildToken(Long userId, Role role, long expirationMs) {
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claims(Map.of("role", role.name()))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Long extractUserId(String token) {
        return Long.parseLong(extractAllClaims(token).getSubject());
    }

    public Role extractRole(String token) {
        String roleName = extractAllClaims(token).get("role", String.class);
        return Role.valueOf(roleName);
    }

    public TokenValidationResponse extractAll(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Long userId = Long.parseLong(claims.getSubject());
            Role role = Role.valueOf(claims.get("role", String.class));
            return new TokenValidationResponse(true, userId, role);
        } catch (Exception e) {
            return new TokenValidationResponse(false, null, null);
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .clockSkewSeconds(clockSkewSeconds)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
}
