package com.itc.auth_service.controller;

import com.itc.auth_service.config.AuthCookieFactory;
import com.itc.auth_service.dto.LoginRequest;
import com.itc.auth_service.dto.RegisterRequest;
import com.itc.auth_service.dto.RegisterResponse;
import com.itc.auth_service.entity.User;
import com.itc.auth_service.service.LoginAttemptService;
import com.itc.auth_service.service.UserService;
import com.itc.auth_service.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final LoginAttemptService loginAttemptService;
    private final AuthCookieFactory cookieFactory;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {

        LoginAttemptService.AuthOutcome outcome =
                loginAttemptService.authenticate(req.email(), req.password());

        if (!outcome.isSuccess()) {
            // One message for every failure mode. Saying "account locked" here would tell
            // an attacker the email is registered and that they reached the threshold.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid email or password"));
        }

        User user = outcome.user();
        String role = user.getRole();

        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), role);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.accessToken(accessToken, jwtUtil.getAccessTokenExpiration()).toString())
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.refreshToken(refreshToken, jwtUtil.getRefreshTokenExpiration()).toString())
                // The tokens are deliberately absent from the body. Returning the access
                // token here defeated the httpOnly cookie: the browser could read it, so
                // it ended up in localStorage where any XSS can exfiltrate it.
                .body(Map.of(
                        "message", "Login successful",
                        "email", user.getEmail(),
                        "role", role
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

    /**
     * Clears the auth cookies. The tokens themselves stay valid until they expire —
     * there is no server-side revocation yet — but the browser stops presenting them.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() {

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireAccessToken().toString())
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireRefreshToken().toString())
                .body(Map.of("message", "Logged out"));
    }
}
