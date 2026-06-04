package com.itc.auth_service.dto;

public record RegisterRequest(
        String fullName,
        String email,
        String password,
        String role   // ROLE_ADMIN / ROLE_USER (optional)
) {}
