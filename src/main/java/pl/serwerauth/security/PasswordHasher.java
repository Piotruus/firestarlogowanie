package pl.serwerauth.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Haszowanie haseł: PBKDF2-HMAC-SHA256, losowa sól 16 B, porównanie w stałym czasie.
 * Format: pbkdf2_sha256$iteracje$sól(b64)$hash(b64)
 */
public final class PasswordHasher {

    private static final String PREFIX = "pbkdf2_sha256";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_ITERATIONS = 5_000_000;
    private static final SecureRandom RNG = new SecureRandom();

    private PasswordHasher() {
    }

    public static String hash(String password, int iterations) {
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);
        byte[] hash = derive(password, salt, iterations);
        return PREFIX + "$" + iterations + "$" + b64(salt) + "$" + b64(hash);
    }

    public static boolean verify(String stored, String password) {
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = derive(password, salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Czy zapisany hash ma słabsze parametry niż obecna konfiguracja. */
    public static boolean needsRehash(String stored, int iterations) {
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return true;
        }
        try {
            return Integer.parseInt(parts[1]) < iterations;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private static byte[] derive(String password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Brak algorytmu " + ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }
}
