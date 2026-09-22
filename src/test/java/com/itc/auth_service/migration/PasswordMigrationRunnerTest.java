package com.itc.auth_service.migration;

import com.itc.auth_service.entity.User;
import com.itc.auth_service.entity.UserRole;
import com.itc.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PasswordMigrationRunnerTest {

    private UserRepository userRepository;
    private PasswordEncoder encoder;
    private PasswordMigrationRunner runner;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        encoder = new BCryptPasswordEncoder(4);
        runner = new PasswordMigrationRunner(userRepository, encoder);
        when(userRepository.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private void dryRun(boolean value) {
        ReflectionTestUtils.setField(runner, "dryRun", value);
    }

    private void withUsers(User... users) {
        Page<User> page = new PageImpl<>(List.of(users), PageRequest.of(0, 200), users.length);
        when(userRepository.findAll(any(PageRequest.class))).thenReturn(page);
    }

    private User user(long id, String password) {
        User user = new User();
        user.setId(id);
        user.setEmail("u" + id + "@example.com");
        user.setPassword(password);
        user.setRole(UserRole.ROLE_USER);
        return user;
    }

    /**
     * The original bug: the prefix check only recognised {@code $2a$}, so a {@code $2b$}
     * or {@code $2y$} hash was treated as plaintext and hashed a second time, leaving the
     * account permanently unable to log in.
     */
    @Test
    void doesNotReEncodeNonDollar2aBcryptVariants() {
        dryRun(false);

        String hash2a = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
        String hash2b = hash2a.replace("$2a$", "$2b$");
        String hash2y = hash2a.replace("$2a$", "$2y$");
        String hash2x = hash2a.replace("$2a$", "$2x$");

        User a = user(1, hash2a);
        User b = user(2, hash2b);
        User y = user(3, hash2y);
        User x = user(4, hash2x);
        withUsers(a, b, y, x);

        runner.run();

        verify(userRepository, never()).saveAll(any());
        assertThat(a.getPassword()).isEqualTo(hash2a);
        assertThat(b.getPassword()).isEqualTo(hash2b);
        assertThat(y.getPassword()).isEqualTo(hash2y);
        assertThat(x.getPassword()).isEqualTo(hash2x);
    }

    @Test
    void recognisesEveryCostFactor() {
        dryRun(false);

        User cheap = user(1, new BCryptPasswordEncoder(4).encode("secret"));
        User dear = user(2, new BCryptPasswordEncoder(12).encode("secret"));
        String cheapHash = cheap.getPassword();
        String dearHash = dear.getPassword();
        withUsers(cheap, dear);

        runner.run();

        assertThat(cheap.getPassword()).isEqualTo(cheapHash);
        assertThat(dear.getPassword()).isEqualTo(dearHash);
    }

    @Test
    void encodesGenuinePlaintextWhenNotDryRunning() {
        dryRun(false);
        User legacy = user(1, "plaintextPassword1!");
        withUsers(legacy);

        runner.run();

        assertThat(legacy.getPassword()).isNotEqualTo("plaintextPassword1!");
        assertThat(encoder.matches("plaintextPassword1!", legacy.getPassword())).isTrue();
        verify(userRepository).saveAll(any());
    }

    @Test
    void dryRunReportsWithoutWriting() {
        dryRun(true);
        User legacy = user(1, "plaintextPassword1!");
        withUsers(legacy);

        runner.run();

        assertThat(legacy.getPassword()).isEqualTo("plaintextPassword1!");
        verify(userRepository, never()).saveAll(any());
    }

    @Test
    void skipsNullAndBlankPasswords() {
        dryRun(false);
        User nullPassword = user(1, null);
        User blankPassword = user(2, "   ");
        withUsers(nullPassword, blankPassword);

        runner.run();

        assertThat(nullPassword.getPassword()).isNull();
        assertThat(blankPassword.getPassword()).isEqualTo("   ");
        verify(userRepository, never()).saveAll(any());
    }
}
