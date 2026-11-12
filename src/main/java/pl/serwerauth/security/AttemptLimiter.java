package pl.serwerauth.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limit nieudanych prób z eskalacją: po {@code maxFails} błędach blokada na {@code baseLockMs},
 * a każda kolejna blokada trwa dwa razy dłużej (maks. 1 godzina).
 * Stan może być zapisywany w bazie ({@link Persistence}), dzięki czemu blokady przeżywają restart serwera.
 */
public final class AttemptLimiter {

    /** Zapisywalny stan jednego klucza (nick albo IP). */
    public record State(int fails, int lockouts, long lockedUntil, long lastFail) {
    }

    public interface Persistence {
        void save(String key, State state);

        void remove(String key);
    }

    private static final long MAX_LOCK_MS = 3_600_000L;
    private static final long FORGET_AFTER_MS = 24L * 3_600_000L;
    /** Częściowe (nieskutkujące blokadą) błędy wygasają po tym czasie bez nowych błędów. */
    private static final long DECAY_MS = 30L * 60_000L;

    private final ConcurrentHashMap<String, State> map = new ConcurrentHashMap<>();
    private volatile int maxFails;
    private volatile long baseLockMs;
    private final Persistence persistence;

    public AttemptLimiter(int maxFails, long baseLockMs, Persistence persistence, Map<String, State> initial) {
        configure(maxFails, baseLockMs);
        this.persistence = persistence;
        if (initial != null) {
            map.putAll(initial);
        }
    }

    /** Zmienia limity bez gubienia aktywnych blokad (używane przy /auth reload). */
    public void configure(int maxFails, long baseLockMs) {
        this.maxFails = Math.max(1, maxFails);
        this.baseLockMs = Math.max(1000L, baseLockMs);
    }

    public AttemptLimiter(int maxFails, long baseLockMs) {
        this(maxFails, baseLockMs, null, null);
    }

    /** Ile milisekund zostało do końca blokady (0 = brak blokady). */
    public long remainingMs(String key) {
        State s = map.get(key);
        if (s == null) return 0L;
        return Math.max(0L, s.lockedUntil() - System.currentTimeMillis());
    }

    /** Rejestruje błąd. Zwraca liczbę pozostałych prób; 0 oznacza, że właśnie nałożono blokadę. */
    public int fail(String key) {
        int[] remaining = new int[1];
        State[] saved = new State[1];
        map.compute(key, (k, cur) -> {
            long now = System.currentTimeMillis();
            State s = cur == null ? new State(0, 0, 0L, now) : cur;
            int previousFails = (now - s.lastFail() > DECAY_MS && s.lockedUntil() <= now) ? 0 : s.fails();
            int fails = previousFails + 1;
            State next;
            if (fails >= maxFails) {
                long lock = Math.min(baseLockMs << Math.min(s.lockouts(), 10), MAX_LOCK_MS);
                remaining[0] = 0;
                next = new State(0, s.lockouts() + 1, now + lock, now);
            } else {
                remaining[0] = maxFails - fails;
                next = new State(fails, s.lockouts(), s.lockedUntil(), now);
            }
            saved[0] = next;
            return next;
        });
        if (persistence != null && saved[0] != null) {
            persistence.save(key, saved[0]);
        }
        return remaining[0];
    }

    public void reset(String key) {
        State old = map.remove(key);
        if (old != null && persistence != null) {
            persistence.remove(key);
        }
    }

    /** Usuwa stare wpisy (wołane okresowo). */
    public void cleanup() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, State> en : map.entrySet()) {
            State s = en.getValue();
            if (now - Math.max(s.lastFail(), s.lockedUntil()) > FORGET_AFTER_MS && map.remove(en.getKey(), s)) {
                if (persistence != null) persistence.remove(en.getKey());
            }
        }
    }
}
