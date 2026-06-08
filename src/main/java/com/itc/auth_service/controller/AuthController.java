package com.itc.auth_service.controller;

import com.itc.auth_service.dto.LoginRequest;
import com.itc.auth_service.dto.RegisterRequest;
import com.itc.auth_service.entity.User;
import com.itc.auth_service.repository.UserRepository;
import com.itc.auth_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3001", allowCredentials = "true")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req,
                                   HttpServletResponse res) {

        // 1️⃣ Find user
        User user = userRepo.findByEmail(req.email())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        // 2️⃣ Validate password
        if (!passwordEncoder.matches(req.password(), user.getPassword())) {
            return ResponseEntity.status(401).body("Invalid email or password");
        }

        // ✅ THIS IS THE CORRECT LINE
        String role = user.getRole(); // ROLE_ADMIN / ROLE_USER

        // 3️⃣ Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), role);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        // 4️⃣ Cookies
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

        // 5️⃣ Response
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
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {

        if (userRepo.findByEmail(req.email()).isPresent()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Email already exists"));
        }

        User user = new User();
        user.setFullName(req.fullName());
        user.setEmail(req.email());
        user.setPassword(passwordEncoder.encode(req.password()));

        // Default role if none supplied
        String role = (req.role() == null || req.role().isBlank())
                ? "ROLE_USER"
                : req.role();

        user.setRole(role);

        userRepo.save(user);

        return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "email", user.getEmail(),
                "role", user.getRole()
        ));
    }
}
