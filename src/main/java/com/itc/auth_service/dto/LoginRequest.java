package com.itc.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Deliberately looser than {@link RegisterRequest}: login must accept whatever is already
 * stored, so it validates only presence and an upper bound. The bound matters because a
 * multi-megabyte password would otherwise be fed straight into bcrypt.
 */
public record LoginRequest(

        @NotBlank(message = "Email is required")
        @Size(max = 120, message = "Email must be 120 characters or fewer")
        String email,

        @NotBlank(message = "Password is required")
        @Size(max = 72, message = "Password must be 72 characters or fewer")
        String password
) {}
