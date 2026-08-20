package com.itc.auth_service.migration;

import com.itc.auth_service.entity.User;
import com.itc.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * One-off migration that re-encodes legacy plaintext passwords with the configured
 * {@code PasswordEncoder}.
 *
 * <p>Disabled unless {@code auth.password-migration.enabled=true}, and reports without
 * writing unless {@code auth.password-migration.dry-run=false}. Both guards are
 * deliberate: re-encoding an already-hashed password is unrecoverable — the original
 * plaintext is gone, so the affected users can never log in again and the only remedy
 * is a forced password reset for everyone.
 *
 * <p>Prefer upgrade-on-login over this class for any future encoder change: verify with
 * the old encoder during authentication, then re-encode from the plaintext you were just
 * given. That path cannot double-encode, because it only ever hashes a known plaintext.
 */
@Component
@ConditionalOnProperty(name = "auth.password-migration.enabled", havingValue = "true")
@RequiredArgsConstructor
public class PasswordMigrationRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(PasswordMigrationRunner.class);

    /**
     * Matches every bcrypt variant, not just {@code $2a$}. The previous prefix check
     * treated {@code $2b$} and {@code $2y$} hashes as legacy plaintext and re-encoded
     * them, permanently locking out those accounts.
     */
    private static final Pattern BCRYPT_HASH =
            Pattern.compile("^\\$2[abxy]\\$\\d{2}\\$[./A-Za-z0-9]{53}$");

    private static final int PAGE_SIZE = 200;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${auth.password-migration.dry-run:true}")
    private boolean dryRun;

    @Override
    public void run(String... args) {

        log.warn("Password migration enabled (dryRun={}). This should not be on in steady state.", dryRun);

        int scanned = 0;
        int migrated = 0;
        int skippedHashed = 0;
        int skippedBlank = 0;

        // Paged rather than findAll(): the user table is unbounded, and loading every
        // row plus its hash into heap is avoidable.
        int pageNumber = 0;
        Page<User> page;

        do {
            page = userRepository.findAll(
                    PageRequest.of(pageNumber, PAGE_SIZE, Sort.by(Sort.Direction.ASC, "id")));

            List<User> toSave = new ArrayList<>();

            for (User user : page.getContent()) {
                scanned++;
                String password = user.getPassword();

                if (password == null || password.isBlank()) {
                    skippedBlank++;
                    continue;
                }

                if (BCRYPT_HASH.matcher(password).matches()) {
                    skippedHashed++;
                    continue;
                }

                migrated++;

                if (!dryRun) {
                    user.setPassword(passwordEncoder.encode(password));
                    toSave.add(user);
                }

                // Log the surrogate id, never the email — this runs at INFO and would
                // otherwise put an account inventory into the log aggregator.
                log.info("{} legacy password for user id={}", dryRun ? "Would migrate" : "Migrated", user.getId());
            }

            if (!toSave.isEmpty()) {
                userRepository.saveAll(toSave);
            }

            pageNumber++;
        } while (page.hasNext());

        log.warn("Password migration finished: scanned={}, {}={}, alreadyHashed={}, blank={}",
                scanned, dryRun ? "wouldMigrate" : "migrated", migrated, skippedHashed, skippedBlank);

        if (dryRun && migrated > 0) {
            log.warn("Dry run — nothing was written. Set auth.password-migration.dry-run=false to apply.");
        }
    }
}
