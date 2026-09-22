package com.itc.auth_service.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
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

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private UserRole role = UserRole.ROLE_USER;

    private int failedAttempts;
    private boolean accountLocked;
    private LocalDateTime lockTime;

}
