package com.itc.auth_service.service;

import com.itc.auth_service.dto.RegisterRequest;
import com.itc.auth_service.entity.User;

import java.util.List;

public interface UserService {

    User registerUser(RegisterRequest request);

    User getUserByEmail(String email);

    User getProfile(String email);

    List<User> getAllUsers();

    User getUserById(Long id);

    User updateUserRole(Long id, String role);

    void deleteUser(Long id);
}
