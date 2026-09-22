package com.itc.auth_service.dto;

import com.itc.auth_service.entity.User;

import java.time.LocalDateTime;

public record UserResponse(
        Long id,
        String fullName,
        String email,
        String role,
        int failedAttempts,
        boolean accountLocked,
        LocalDateTime lockTime
) {
    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().name(),
                user.getFailedAttempts(),
                user.isAccountLocked(),
                user.getLockTime()
        );
    }
}
