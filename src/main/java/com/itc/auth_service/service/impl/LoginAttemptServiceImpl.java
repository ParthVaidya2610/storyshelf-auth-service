package com.itc.auth_service.service.impl;

import com.itc.auth_service.entity.User;
import com.itc.auth_service.repository.UserRepository;
import com.itc.auth_service.service.LoginAttemptService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class LoginAttemptServiceImpl implements LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${auth.lockout.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${auth.lockout.duration:PT15M}")
    private Duration lockoutDuration;

    /**
     * Hash of a random value nobody knows, used to burn the same CPU time on a missing
     * account as on a real one. Without it an unknown email returns in microseconds while
     * a known email costs a full bcrypt verification — a timing oracle that enumerates
     * registered users however generic the response body is.
     *
     * <p>Generated with the live encoder rather than hardcoded, so it is always a
     * well-formed hash at exactly the configured cost factor. A malformed literal would
     * make {@code matches()} bail out early and silently undo the equalisation.
     */
    private String dummyHash;

    @PostConstruct
    void initDummyHash() {
        dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Override
    public AuthOutcome authenticate(String email, String rawPassword) {

        Optional<User> found = email == null
                ? Optional.empty()
                : userRepository.findByEmail(email);

        if (found.isEmpty()) {
            passwordEncoder.matches(rawPassword == null ? "" : rawPassword, dummyHash);
            return new AuthOutcome(Status.INVALID_CREDENTIALS, null);
        }

        User user = found.get();

        if (isLocked(user)) {
            // Do not extend the lock on attempts made while already locked; otherwise an
            // attacker can keep a victim locked out indefinitely.
            log.warn("Rejected sign-in for locked account id={}", user.getId());
            return new AuthOutcome(Status.LOCKED, null);
        }

        // matches() tolerates a null raw password by contract in our call path only
        // because we normalise it here; BCryptPasswordEncoder itself throws on null.
        boolean passwordOk = rawPassword != null
                && passwordEncoder.matches(rawPassword, user.getPassword());

        if (!passwordOk) {
            registerFailure(user);
            return new AuthOutcome(Status.INVALID_CREDENTIALS, null);
        }

        resetFailures(user);
        return new AuthOutcome(Status.SUCCESS, user);
    }

    /**
     * True while the account is locked and the cool-off has not elapsed. An expired lock
     * is cleared here so the account recovers without admin intervention.
     */
    private boolean isLocked(User user) {

        if (!user.isAccountLocked()) {
            return false;
        }

        LocalDateTime lockedAt = user.getLockTime();

        // A lock with no timestamp is treated as indefinite rather than as unlocked —
        // failing open here would let a corrupt row bypass the lockout entirely.
        if (lockedAt == null) {
            return true;
        }

        if (lockedAt.plus(lockoutDuration).isAfter(LocalDateTime.now())) {
            return true;
        }

        user.setAccountLocked(false);
        user.setFailedAttempts(0);
        user.setLockTime(null);
        userRepository.save(user);
        return false;
    }

    private void registerFailure(User user) {

        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);

        if (attempts >= maxFailedAttempts) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now());
            log.warn("Locked account id={} after {} consecutive failed sign-ins", user.getId(), attempts);
        }

        userRepository.save(user);
    }

    private void resetFailures(User user) {

        if (user.getFailedAttempts() == 0 && !user.isAccountLocked() && user.getLockTime() == null) {
            return;
        }

        user.setFailedAttempts(0);
        user.setAccountLocked(false);
        user.setLockTime(null);
        userRepository.save(user);
    }
}
