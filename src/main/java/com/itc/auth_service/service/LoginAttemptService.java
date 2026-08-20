package com.itc.auth_service.service;

import com.itc.auth_service.entity.User;

public interface LoginAttemptService {

    /**
     * Authenticates a credential pair, maintaining the failed-attempt counters.
     *
     * @return the authenticated user, or {@link AuthOutcome#user()} of {@code null} when
     *         authentication failed for any reason. Callers must not distinguish between
     *         the failure reasons in their response body.
     */
    AuthOutcome authenticate(String email, String rawPassword);

    enum Status { SUCCESS, INVALID_CREDENTIALS, LOCKED }

    record AuthOutcome(Status status, User user) {

        public boolean isSuccess() {
            return status == Status.SUCCESS;
        }
    }
}
