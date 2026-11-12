package pl.serwerauth.security;

import java.util.ArrayDeque;
import java.util.concurrent.ConcurrentHashMap;

/** Limit prób połączenia z jednego adresu IP w oknie czasowym (ochrona przed zalewaniem botami). */
public final class ConnectionThrottle {

    private final ConcurrentHashMap<String, ArrayDeque<Long>> map = new ConcurrentHashMap<>();
    private final int max;
    private final long windowMs;

    public ConnectionThrottle(int max, long windowMs) {
        this.max = Math.max(1, max);
        this.windowMs = windowMs;
    }

    public boolean allow(String ip) {
        long now = System.currentTimeMillis();
        ArrayDeque<Long> q = map.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) {
                q.pollFirst();
            }
            if (q.size() >= max) {
                return false;
            }
            q.addLast(now);
            return true;
        }
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        map.entrySet().removeIf(en -> {
            ArrayDeque<Long> q = en.getValue();
            synchronized (q) {
                while (!q.isEmpty() && now - q.peekFirst() > windowMs) {
                    q.pollFirst();
                }
                return q.isEmpty();
            }
        });
    }
}
