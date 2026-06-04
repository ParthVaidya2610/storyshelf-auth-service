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

            return path.startsWith("/api/auth/login")
                    || path.startsWith("/api/auth/register")
                    || path.startsWith("/api/auth/refresh-token")
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

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    email,
                                    null,
                                    List.of(new SimpleGrantedAuthority(role))
                            );

                    SecurityContextHolder.getContext().setAuthentication(auth);

                } catch (Exception e) {
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


