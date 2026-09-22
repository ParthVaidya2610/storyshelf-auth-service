    package com.itc.auth_service.security;

    import com.itc.auth_service.entity.User;
    import com.itc.auth_service.entity.UserRole;
    import com.itc.auth_service.repository.UserRepository;
    import lombok.RequiredArgsConstructor;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.stereotype.Service;

    import java.util.List;

    @Service
    @RequiredArgsConstructor
    public class CustomUserDetailsService implements UserDetailsService {

        private final UserRepository userRepository;

        @Override
        public UserDetails loadUserByUsername(String email)
                throws UsernameNotFoundException {

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User not found: " + email));

            UserRole role = user.getRole();

            if (role == null) {
                throw new IllegalStateException("User role is missing for: " + email);
            }

            return org.springframework.security.core.userdetails.User
                    .withUsername(user.getEmail())
                    .password(user.getPassword())
                    .authorities(List.of(new SimpleGrantedAuthority(role.name())))
                    .build();
        }

    }