package com.goylik.auth_service.model.dto.response;

import com.goylik.auth_service.model.enums.Role;

public record TokenValidationResponse(
        boolean valid,
        Long userId,
        Role role
) {
}
