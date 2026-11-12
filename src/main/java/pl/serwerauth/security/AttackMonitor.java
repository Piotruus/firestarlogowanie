package pl.serwerauth.security;

import java.util.ArrayDeque;

/**
 * Wykrywa nagły zalew połączeń (atak botów). Gdy w oknie czasowym pojawi się co najmniej
 * {@code threshold} prób połączenia, włącza "tryb ataku" na {@code durationMs}; dopóki zalew trwa, tryb się przedłuża.
 */
public final class AttackMonitor {

    private final ArrayDeque<Long> window = new ArrayDeque<>();
    private final int threshold;
    private final long windowMs;
    private final long durationMs;
    private volatile long attackUntil;

    public AttackMonitor(int threshold, long windowMs, long durationMs) {
        this.threshold = Math.max(2, threshold);
        this.windowMs = windowMs;
        this.durationMs = durationMs;
    }

    /** Rejestruje próbę połączenia. Zwraca true tylko w chwili, gdy tryb ataku WŁAŚNIE się włączył. */
    public synchronized boolean record() {
        long now = System.currentTimeMillis();
        while (!window.isEmpty() && now - window.peekFirst() > windowMs) {
            window.pollFirst();
        }
        window.addLast(now);
        if (window.size() >= threshold) {
            boolean wasActive = attackUntil > now;
            attackUntil = now + durationMs;
            return !wasActive;
        }
        return false;
    }

    public boolean isActive() {
        return attackUntil > System.currentTimeMillis();
    }
}
