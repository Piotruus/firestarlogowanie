package pl.serwerauth.security;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.geom.CubicCurve2D;
import java.awt.geom.QuadCurve2D;
import java.awt.image.BufferedImage;
import java.security.SecureRandom;

/**
 * Generator captchy 128x128 (rozmiar mapy Minecrafta): losowy kod, obrócone i przesunięte znaki,
 * zakrzywione linie, szum oraz falowe zniekształcenie obrazu. Używa SecureRandom.
 */
public final class CaptchaGenerator {

    public static final int SIZE = 128;
    /** Bez znaków mylących: I, O, Q, 0, 1. */
    private static final String CHARSET = "ABCDEFGHJKLMNPRSTUVWXYZ23456789";
    private static final SecureRandom RNG = new SecureRandom();

    private CaptchaGenerator() {
    }

    public static String randomCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARSET.charAt(RNG.nextInt(CHARSET.length())));
        }
        return sb.toString();
    }

    public static BufferedImage render(String code) {
        BufferedImage img = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            g.setPaint(new GradientPaint(0, 0, light(), SIZE, SIZE, light()));
            g.fillRect(0, 0, SIZE, SIZE);

            // linie w tle
            for (int i = 0; i < 8; i++) {
                g.setColor(mid());
                g.setStroke(new BasicStroke(1f + RNG.nextFloat() * 1.5f));
                g.draw(new QuadCurve2D.Float(rf(), rf(), rf(), rf(), rf(), rf()));
            }

            // znaki
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 34));
            FontMetrics fm = g.getFontMetrics();
            int n = code.length();
            float slot = (SIZE - 14f) / n;
            for (int i = 0; i < n; i++) {
                char ch = code.charAt(i);
                double cx = 7 + slot * i + slot / 2.0;
                double cy = SIZE / 2.0 + (RNG.nextDouble() * 16 - 8);
                AffineTransform old = g.getTransform();
                g.rotate((RNG.nextDouble() - 0.5) * 0.6, cx, cy);
                g.setColor(dark());
                g.drawString(String.valueOf(ch),
                        (float) (cx - fm.charWidth(ch) / 2.0),
                        (float) (cy + fm.getAscent() / 2.6));
                g.setTransform(old);
            }

            // linie przecinające tekst
            for (int i = 0; i < 4; i++) {
                Color d = dark();
                g.setColor(new Color(d.getRed(), d.getGreen(), d.getBlue(), 170));
                g.setStroke(new BasicStroke(1.2f + RNG.nextFloat() * 0.8f));
                g.draw(new CubicCurve2D.Float(0, rf(), rf(), rf(), rf(), rf(), SIZE, rf()));
            }

            // szum punktowy
            for (int i = 0; i < 220; i++) {
                img.setRGB(RNG.nextInt(SIZE), RNG.nextInt(SIZE),
                        new Color(RNG.nextInt(256), RNG.nextInt(256), RNG.nextInt(256)).getRGB());
            }
        } finally {
            g.dispose();
        }
        return warp(img);
    }

    /** Falowe zniekształcenie w obu osiach. */
    private static BufferedImage warp(BufferedImage src) {
        BufferedImage out = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_RGB);
        double ax = 1.5 + RNG.nextDouble() * 1.8, px = 34 + RNG.nextDouble() * 30, phx = RNG.nextDouble() * Math.PI * 2;
        double ay = 1.0 + RNG.nextDouble() * 1.5, py = 30 + RNG.nextDouble() * 30, phy = RNG.nextDouble() * Math.PI * 2;
        for (int y = 0; y < SIZE; y++) {
            for (int x = 0; x < SIZE; x++) {
                int sx = x + (int) Math.round(Math.sin(2 * Math.PI * y / px + phx) * ax);
                int sy = y + (int) Math.round(Math.sin(2 * Math.PI * x / py + phy) * ay);
                sx = Math.max(0, Math.min(SIZE - 1, sx));
                sy = Math.max(0, Math.min(SIZE - 1, sy));
                out.setRGB(x, y, src.getRGB(sx, sy));
            }
        }
        return out;
    }

    private static float rf() {
        return RNG.nextFloat() * SIZE;
    }

    private static Color light() {
        return new Color(170 + RNG.nextInt(80), 170 + RNG.nextInt(80), 170 + RNG.nextInt(80));
    }

    private static Color mid() {
        return new Color(90 + RNG.nextInt(100), 90 + RNG.nextInt(100), 90 + RNG.nextInt(100));
    }

    private static Color dark() {
        return new Color(RNG.nextInt(100), RNG.nextInt(100), RNG.nextInt(100));
    }
}
