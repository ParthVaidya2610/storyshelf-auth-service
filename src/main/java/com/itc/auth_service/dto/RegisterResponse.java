package com.itc.auth_service.dto;

public record RegisterResponse(
        String message,
        String email,
        String role
) {}
