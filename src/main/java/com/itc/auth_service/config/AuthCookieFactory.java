package com.itc.auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Builds the auth cookies from configuration so the security-relevant attributes are set
 * in exactly one place.
 *
 * <p>{@code secure} defaults to true: the previous hardcoded {@code secure(false)} meant
 * both the access and refresh token travelled in cleartext and could be lifted off the
 * wire by anyone on the network path. Override it to false only for local HTTP work.
 */
@Component
public class AuthCookieFactory {

    public static final String ACCESS_TOKEN = "accessToken";
    public static final String REFRESH_TOKEN = "refreshToken";

    @Value("${app.cookie.secure:true}")
    private boolean secure;

    /**
     * Strict by default. These cookies are only ever read by this service's own XHR
     * calls, so there is no legitimate cross-site navigation that needs to carry them —
     * and Strict is what keeps CSRF off the table while csrf() stays disabled.
     */
    @Value("${app.cookie.same-site:Strict}")
    private String sameSite;

    @Value("${app.cookie.domain:}")
    private String domain;

    public ResponseCookie accessToken(String token, Duration maxAge) {
        return build(ACCESS_TOKEN, token, maxAge);
    }

    public ResponseCookie refreshToken(String token, Duration maxAge) {
        return build(REFRESH_TOKEN, token, maxAge);
    }

    /** Zero-length, zero-age cookies that evict the pair from the browser on sign-out. */
    public ResponseCookie expireAccessToken() {
        return build(ACCESS_TOKEN, "", Duration.ZERO);
    }

    public ResponseCookie expireRefreshToken() {
        return build(REFRESH_TOKEN, "", Duration.ZERO);
    }

    private ResponseCookie build(String name, String value, Duration maxAge) {

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path("/")
                .maxAge(maxAge);

        if (!domain.isBlank()) {
            builder.domain(domain);

        }

        return builder.build();
    }
}
