package com.itc.auth_service.controller;

import com.itc.auth_service.dto.LoginRequest;
import com.itc.auth_service.dto.RegisterRequest;
import com.itc.auth_service.entity.User;
import com.itc.auth_service.repository.RoleRepository;
import com.itc.auth_service.repository.UserRepository;
import com.itc.auth_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.itc.auth_service.dto.RegisterResponse;
import com.itc.auth_service.service.UserService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3001", allowCredentials = "true")
@RequiredArgsConstructor
public class AuthController {

    private static final String DEFAULT_ROLE = "ROLE_USER";
    private final RoleRepository roleRepository;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req,
                                   HttpServletResponse res) {

        User user = userRepo.findByEmail(req.email()).orElse(null);

        if (user == null ||
                !passwordEncoder.matches(req.password(), user.getPassword())) {

            return ResponseEntity.status(401)
                    .body(Map.of("message", "Invalid email or password"));
        }

        String role = user.getRole();
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), role);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        ResponseCookie accessCookie = ResponseCookie.from("accessToken", accessToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(15 * 60)
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(Map.of(
                        "message", "Login successful",
                        "email", user.getEmail(),
                        "role", role,
                        "accessToken", accessToken
                ));
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest req) {

        User user = userService.registerUser(req);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterResponse(
                        "User registered successfully",
                        user.getEmail(),
                        user.getRole()
                ));
    }
}
