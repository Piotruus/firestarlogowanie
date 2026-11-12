package pl.serwerauth.security;

import java.util.ArrayList;
import java.util.List;

/**
 * Zapamiętuje kierunki kolejnych kroków gracza. Prosty bot idzie cały czas prosto,
 * człowiek (poproszony o to) zmienia kierunek — {@link #hasTurn(double)} to sprawdza.
 */
public final class HeadingTracker {

    private static final int MAX_TRACKED = 40;

    private final List<Double> headings = new ArrayList<>();

    public void add(double dx, double dz) {
        if (dx == 0.0 && dz == 0.0) return;
        if (headings.size() >= MAX_TRACKED) headings.remove(0);
        headings.add(Math.atan2(dz, dx));
    }

    /** Czy istnieją dwa kroki, których kierunki różnią się o co najmniej {@code minDegrees} stopni. */
    public boolean hasTurn(double minDegrees) {
        double min = Math.toRadians(minDegrees);
        for (int i = 0; i < headings.size(); i++) {
            for (int j = i + 1; j < headings.size(); j++) {
                double d = Math.abs(headings.get(i) - headings.get(j));
                if (d > Math.PI) d = 2 * Math.PI - d;
                if (d >= min) return true;
            }
        }
        return false;
    }

    public int size() {
        return headings.size();
    }

    public void clear() {
        headings.clear();
    }
}
