package com.itc.auth_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.private-key-path}")
    private Resource privateKeyResource;

    @Value("${jwt.public-key-path}")
    private Resource publicKeyResource;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final long ACCESS_EXP = 15 * 60 * 1000;          // 15 min
    private static final long REFRESH_EXP = 7 * 24 * 60 * 60 * 1000L; // 7 days

    @PostConstruct
    public void loadKeys() {
        try {
            // ===== PRIVATE KEY =====
            String privateKeyContent = new String(
                    privateKeyResource.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8
            )
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] privateBytes = Base64.getDecoder().decode(privateKeyContent);
            privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

            // ===== PUBLIC KEY =====
            String publicKeyContent = new String(
                    publicKeyResource.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8
            )
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] publicBytes = Base64.getDecoder().decode(publicKeyContent);
            publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(publicBytes));

        } catch (Exception e) {
            throw new IllegalStateException("❌ Failed to load RSA keys", e);
        }
    }

    // =============================
    // ACCESS TOKEN (RS384)
    // =============================
    public String generateAccessToken(String email, String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXP))
                .signWith(privateKey, SignatureAlgorithm.RS384)
                .compact();
    }

    // =============================
    // REFRESH TOKEN (RS384)
    // =============================
    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXP))
                .signWith(privateKey, SignatureAlgorithm.RS384)
                .compact();
    }

    // =============================
    // VALIDATION
    // =============================
    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
