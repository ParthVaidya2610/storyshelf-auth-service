package com.itc.auth_service.migration;

import com.itc.auth_service.entity.User;
import com.itc.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PasswordMigrationRunner implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {

        System.out.println("🔐 Migrating legacy passwords...");

        userRepository.findAll().forEach(user -> {

            String password = user.getPassword();

            // already BCrypt → skip
            if (password != null && password.startsWith("$2a$")) {
                return;
            }

            if (password == null || password.isBlank()) {
                return;
            }

            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);

            System.out.println("✅ Migrated: " + user.getEmail());
        });

        System.out.println("🎉 Password migration completed");
    }
}
