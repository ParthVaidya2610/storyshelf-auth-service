package com.itc.auth_service.service.impl;

import com.itc.auth_service.dto.RegisterRequest;
import com.itc.auth_service.entity.User;
import com.itc.auth_service.entity.UserRole;
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

    private static final String ROLE_PREFIX = "ROLE_";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(RegisterRequest request) {

        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException(
                    "Email already exists: " + request.email()
            );
        }

        User user = new User();
        user.setFullName(request.fullName());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(UserRole.ROLE_USER);

        return userRepository.save(user);
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

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found: " + id));
    }

    @Override
    public User updateUserRole(Long id, String role) {
        User user = getUserById(id);
        user.setRole(resolveRole(role));
        return userRepository.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalArgumentException("User not found: " + id);
        }

        userRepository.deleteById(id);
    }

    private UserRole resolveRole(String role) {
        if (role == null || role.isBlank()) {
            return UserRole.ROLE_USER;
        }

        String normalizedRole = role.trim().toUpperCase();
        if (!normalizedRole.startsWith(ROLE_PREFIX)) {
            normalizedRole = ROLE_PREFIX + normalizedRole;
        }

        try {
            return UserRole.valueOf(normalizedRole);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unsupported role: " + role);
        }
    }
}
