package com.example.loginmonitoring.service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.stereotype.Service;

import com.example.loginmonitoring.entity.LoginAttempt;

/**
 * Knows which devices each user is signed in on, so users can see their active sessions and
 * sign out other devices. Spring Security's {@link SessionRegistry} holds the sessions; this
 * class adds the device, IP and location of the login that started each one.
 *
 * <p>Session ids are secrets (whoever has one is logged in), so pages only ever see a random
 * "handle" that stands for a session, never the id itself. Sessions live in memory, like the
 * sessions themselves: after a restart everyone has to log in again anyway.
 */
@Service
public class SessionTracker implements ApplicationListener<HttpSessionDestroyedEvent> {

    public record SessionView(String handle, String ip, String device, String deviceType, String location,
                              LocalDateTime loginAt, LocalDateTime lastActive, boolean current) {
    }

    private record SessionMeta(String handle, String username, String ip, String device, String deviceType,
                               String location, LocalDateTime loginAt) {
    }

    private final SessionRegistry sessionRegistry;
    private final Map<String, SessionMeta> metaBySessionId = new ConcurrentHashMap<>();

    public SessionTracker(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public void register(String sessionId, String username, LoginAttempt attempt, String location) {
        metaBySessionId.put(sessionId, new SessionMeta(UUID.randomUUID().toString(), username,
                attempt.getIpAddress(), attempt.getDeviceLabel(), attempt.getDeviceType(), location,
                attempt.getAttemptedAt()));
    }

    /** Active sessions of a user, current one first. */
    public List<SessionView> sessionsOf(String username, String currentSessionId) {
        List<SessionView> views = new ArrayList<>();
        for (SessionInformation info : sessionsFor(username)) {
            SessionMeta meta = metaBySessionId.get(info.getSessionId());
            LocalDateTime lastActive = LocalDateTime.ofInstant(info.getLastRequest().toInstant(), ZoneOffset.UTC);
            boolean current = info.getSessionId().equals(currentSessionId);
            if (meta == null) {
                views.add(new SessionView(null, "-", "Unknown device", null, "-", null, lastActive, current));
            } else {
                views.add(new SessionView(meta.handle(), meta.ip(), meta.device(), meta.deviceType(), meta.location(),
                        meta.loginAt(), lastActive, current));
            }
        }
        views.sort(Comparator.comparing(SessionView::current).reversed()
                .thenComparing(SessionView::lastActive, Comparator.reverseOrder()));
        return views;
    }

    /** Signs out every session of the user except the current one. */
    public int expireOthers(String username, String currentSessionId) {
        int count = 0;
        for (SessionInformation info : sessionsFor(username)) {
            if (!info.getSessionId().equals(currentSessionId)) {
                info.expireNow();
                count++;
            }
        }
        return count;
    }

    /** Signs out one session of the user, found by its handle. */
    public boolean expireByHandle(String username, String handle) {
        for (SessionInformation info : sessionsFor(username)) {
            SessionMeta meta = metaBySessionId.get(info.getSessionId());
            if (meta != null && meta.handle().equals(handle)) {
                info.expireNow();
                return true;
            }
        }
        return false;
    }

    /** Signs out every session of the user (e.g. when an admin disables the account). */
    public int expireAll(String username) {
        List<SessionInformation> sessions = sessionsFor(username);
        sessions.forEach(SessionInformation::expireNow);
        return sessions.size();
    }

    @Override
    public void onApplicationEvent(HttpSessionDestroyedEvent event) {
        metaBySessionId.remove(event.getId());
    }

    private List<SessionInformation> sessionsFor(String username) {
        List<SessionInformation> result = new ArrayList<>();
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String name = principal instanceof UserDetails details ? details.getUsername() : String.valueOf(principal);
            if (name.equalsIgnoreCase(username)) {
                result.addAll(sessionRegistry.getAllSessions(principal, false));
            }
        }
        return result;
    }
}
