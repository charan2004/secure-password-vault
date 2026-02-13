package com.securevault.auth;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory session manager for CLI application
 */
@Component
public class SessionManager {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private static final int SESSION_TIMEOUT_MINUTES = 30;

    public Session createSession(User user) {
        Session session = new Session(user.getId(), user.getUsername(), user.getRole());
        sessions.put(session.getSessionId(), session);
        return session;
    }

    public Optional<Session> getSession(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session != null) {
            if (session.isExpired(SESSION_TIMEOUT_MINUTES)) {
                sessions.remove(sessionId);
                return Optional.empty();
            }
            session.updateLastAccessed();
        }
        return Optional.ofNullable(session);
    }

    public void invalidateSession(String sessionId) {
        sessions.remove(sessionId);
    }

    public void invalidateAllSessions() {
        sessions.clear();
    }
}
