package com.itc.auth_service.service.impl;

import com.itc.auth_service.dto.RegisterRequest;

import com.itc.auth_service.entity.User;

import com.itc.auth_service.repository.UserRepository;
import com.itc.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void registerUser(RegisterRequest request) {

        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException(
                    "Email already exists: " + request.email()
            );
        }

        User user = new User();
        user.setFullName(request.fullName());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));

        // ✅ STRING ROLE (NO ENTITY, NO REPOSITORY)
        String role = (request.role() != null && !request.role().isBlank())
                ? request.role()
                : "ROLE_USER";

        user.setRole(role);

        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found: " + email));
    }

    @Override
    @Transactional(readOnly = true)
    public User getProfile(String email) {
        return getUserByEmail(email);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}

