    package com.itc.auth_service.security;

    import com.itc.auth_service.util.JwtUtil;
    import io.jsonwebtoken.Claims;
    import jakarta.servlet.FilterChain;
    import jakarta.servlet.ServletException;
    import jakarta.servlet.http.Cookie;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.stereotype.Component;
    import org.springframework.web.filter.OncePerRequestFilter;

    import java.io.IOException;
    import java.util.Collections;
    import java.util.List;

    @Component
    public class JwtAuthenticationFilter extends OncePerRequestFilter {

        @Autowired
        private JwtUtil jwtUtil;

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {

            String path = request.getServletPath();

            // refresh-token was listed here but no such endpoint exists; skipping a
            // route that does not exist only makes it easier to add one later that
            // silently bypasses the filter.
            return path.startsWith("/api/auth/login")
                    || path.startsWith("/api/auth/register")
                    || path.startsWith("/api/auth/logout")
                    || request.getMethod().equalsIgnoreCase("OPTIONS");
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain)
                throws ServletException, IOException {

            String token = extractAccessToken(request);

            if (token != null) {
                try {
                    Claims claims = jwtUtil.extractClaims(token);

                    String email = claims.getSubject();
                    String role = claims.get("role", String.class);

                    // Refresh tokens are signed by the same key and carry no role claim,
                    // so they parse cleanly here. Previously the only thing stopping one
                    // being used as an access token was SimpleGrantedAuthority throwing
                    // on a null argument and landing in the catch below — an accident,
                    // not a control. Reject explicitly instead.
                    if (email == null || email.isBlank() || role == null || role.isBlank()) {
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                    }

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    email,
                                    null,
                                    List.of(new SimpleGrantedAuthority(role))
                            );

                    SecurityContextHolder.getContext().setAuthentication(auth);

                } catch (Exception e) {
                    // Expired or tampered token: proceed unauthenticated and let the
                    // authorization rules produce the 401.
                    SecurityContextHolder.clearContext();
                }
            }

            filterChain.doFilter(request, response);
        }

        private String extractAccessToken(HttpServletRequest request) {

            if (request.getCookies() == null) return null;

            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
            return null;
        }
    }


