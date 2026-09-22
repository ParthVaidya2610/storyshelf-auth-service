package com.itc.auth_service.service.impl;

import com.itc.auth_service.entity.User;
import com.itc.auth_service.entity.UserRole;
import com.itc.auth_service.repository.UserRepository;
import com.itc.auth_service.service.LoginAttemptService.AuthOutcome;
import com.itc.auth_service.service.LoginAttemptService.Status;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LoginAttemptServiceImplTest {

    private static final String EMAIL = "user@example.com";
    private static final String PASSWORD = "Correct-Horse-1!";
    private static final int MAX_ATTEMPTS = 3;

    private UserRepository userRepository;
    private LoginAttemptServiceImpl service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        // Cost 4 keeps the suite fast; the logic under test is cost-independent.
        PasswordEncoder encoder = new BCryptPasswordEncoder(4);

        service = new LoginAttemptServiceImpl(userRepository, encoder);
        ReflectionTestUtils.setField(service, "maxFailedAttempts", MAX_ATTEMPTS);
        ReflectionTestUtils.setField(service, "lockoutDuration", Duration.ofMinutes(15));
        service.initDummyHash();

        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private User storedUser() {
        User user = new User();
        user.setId(1L);
        user.setEmail(EMAIL);
        user.setPassword(new BCryptPasswordEncoder(4).encode(PASSWORD));
        user.setRole(UserRole.ROLE_USER);
        return user;
    }

    private void existing(User user) {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    }

    @Test
    void unknownEmailFailsWithoutRevealingAnything() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        AuthOutcome outcome = service.authenticate("nobody@example.com", PASSWORD);

        assertThat(outcome.status()).isEqualTo(Status.INVALID_CREDENTIALS);
        assertThat(outcome.user()).isNull();
    }

    @Test
    void nullEmailIsRejectedWithoutHittingTheRepository() {
        AuthOutcome outcome = service.authenticate(null, PASSWORD);

        assertThat(outcome.status()).isEqualTo(Status.INVALID_CREDENTIALS);
    }

    @Test
    void nullPasswordIsRejectedRatherThanThrowing() {
        existing(storedUser());

        AuthOutcome outcome = service.authenticate(EMAIL, null);

        assertThat(outcome.status()).isEqualTo(Status.INVALID_CREDENTIALS);
    }

    @Test
    void correctPasswordSucceeds() {
        existing(storedUser());

        AuthOutcome outcome = service.authenticate(EMAIL, PASSWORD);

        assertThat(outcome.isSuccess()).isTrue();
        assertThat(outcome.user().getEmail()).isEqualTo(EMAIL);
    }

    @Test
    void eachFailureIncrementsTheCounter() {
        User user = storedUser();
        existing(user);

        service.authenticate(EMAIL, "wrong");
        assertThat(user.getFailedAttempts()).isEqualTo(1);

        service.authenticate(EMAIL, "wrong");
        assertThat(user.getFailedAttempts()).isEqualTo(2);
        assertThat(user.isAccountLocked()).isFalse();
    }

    @Test
    void accountLocksOnReachingTheThreshold() {
        User user = storedUser();
        existing(user);

        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            service.authenticate(EMAIL, "wrong");
        }

        assertThat(user.isAccountLocked()).isTrue();
        assertThat(user.getLockTime()).isNotNull();
    }

    @Test
    void lockedAccountRejectsEvenTheCorrectPassword() {
        User user = storedUser();
        user.setAccountLocked(true);
        user.setLockTime(LocalDateTime.now());
        existing(user);

        AuthOutcome outcome = service.authenticate(EMAIL, PASSWORD);

        assertThat(outcome.status()).isEqualTo(Status.LOCKED);
        assertThat(outcome.user()).isNull();
    }

    @Test
    void attemptsDuringLockoutDoNotExtendIt() {
        User user = storedUser();
        user.setAccountLocked(true);
        user.setFailedAttempts(MAX_ATTEMPTS);
        LocalDateTime lockedAt = LocalDateTime.now().minusMinutes(5);
        user.setLockTime(lockedAt);
        existing(user);

        service.authenticate(EMAIL, "wrong");
        service.authenticate(EMAIL, "wrong");

        assertThat(user.getLockTime()).isEqualTo(lockedAt);
        assertThat(user.getFailedAttempts()).isEqualTo(MAX_ATTEMPTS);
    }

    @Test
    void expiredLockClearsItselfAndAllowsSignIn() {
        User user = storedUser();
        user.setAccountLocked(true);
        user.setFailedAttempts(MAX_ATTEMPTS);
        user.setLockTime(LocalDateTime.now().minusMinutes(16));
        existing(user);

        AuthOutcome outcome = service.authenticate(EMAIL, PASSWORD);

        assertThat(outcome.isSuccess()).isTrue();
        assertThat(user.isAccountLocked()).isFalse();
        assertThat(user.getFailedAttempts()).isZero();
        assertThat(user.getLockTime()).isNull();
    }

    @Test
    void lockWithNoTimestampIsTreatedAsIndefinite() {
        User user = storedUser();
        user.setAccountLocked(true);
        user.setLockTime(null);
        existing(user);

        assertThat(service.authenticate(EMAIL, PASSWORD).status()).isEqualTo(Status.LOCKED);
    }

    @Test
    void successResetsAPartialFailureStreak() {
        User user = storedUser();
        existing(user);

        service.authenticate(EMAIL, "wrong");
        service.authenticate(EMAIL, "wrong");
        assertThat(user.getFailedAttempts()).isEqualTo(2);

        AuthOutcome outcome = service.authenticate(EMAIL, PASSWORD);

        assertThat(outcome.isSuccess()).isTrue();
        assertThat(user.getFailedAttempts()).isZero();
    }
}
