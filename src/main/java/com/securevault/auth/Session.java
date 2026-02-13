package com.securevault.auth;

import lombok.Getter;
import java.time.LocalDateTime;
import java.util.UUID;

@Getter
public class Session {
    private final String sessionId;
    private final UUID userId;
    private final String username;
    private final Role role;
    private final LocalDateTime createdAt;
    private LocalDateTime lastAccessedAt;

    public Session(UUID userId, String username, Role role) {
        this.sessionId = UUID.randomUUID().toString();
        this.userId = userId;
        this.username = username;
        this.role = role;
        this.createdAt = LocalDateTime.now();
        this.lastAccessedAt = LocalDateTime.now();
    }

    public void updateLastAccessed() {
        this.lastAccessedAt = LocalDateTime.now();
    }

    public boolean isExpired(int timeoutMinutes) {
        return lastAccessedAt.plusMinutes(timeoutMinutes).isBefore(LocalDateTime.now());
    }
}
