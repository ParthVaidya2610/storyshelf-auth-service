package com.itc.auth_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fullName;

    @Column(unique = true, nullable = false)
    private String email;

    private String password;

    // 🔥 FIX: STRING ROLE (NOT ENTITY)
    @Column(nullable = false)
    private String role;

    private int failedAttempts;
    private boolean accountLocked;
    private LocalDateTime lockTime;

}