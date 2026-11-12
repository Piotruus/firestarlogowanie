package pl.serwerauth.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Wymagania dla haseł. Zwraca listę problemów (pusta = hasło poprawne). */
public final class PasswordPolicy {

    public enum Problem {
        ZA_KROTKIE, ZA_DLUGIE, BRAK_DUZEJ, BRAK_MALEJ, BRAK_CYFRY, BRAK_ZNAKU,
        SPACJE, ZAWIERA_NICK, POPULARNE, POWTORZENIA, SEKWENCJA;

        /** Klucz wiadomości w messages.yml. */
        public String key() {
            return "polityka." + name().toLowerCase(Locale.ROOT).replace('_', '-');
        }
    }

    private static final Set<String> COMMON_EXACT = Set.of(
            "123456", "12345678", "123456789", "1234567890", "111111", "000000",
            "qwerty", "qwerty123", "abc123", "password", "haslo", "admin", "admin123",
            "test", "test123", "login", "minecraft", "letmein", "welcome", "monkey");

    private static final List<String> COMMON_PARTS = List.of(
                    "password", "haslo123", "qwerty", "minecraft", "letmein", "welcome",
                    "iloveyou", "zaq12wsx", "polska", "kocham", "dragon", "master",
                    "superman", "football", "shadow", "sunshine", "trustno1", "serwer",
                    "admin123", "1q2w3e4r")
            .stream().map(PasswordPolicy::normalize).toList();

    private static final List<String> SEQUENCES = List.of(
            "abcdefghijklmnopqrstuvwxyz", "0123456789",
            "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsxedc");

    private PasswordPolicy() {
    }

    public static List<Problem> validate(String password, String nick, int min, int max) {
        List<Problem> out = new ArrayList<>();
        if (password.length() < min) out.add(Problem.ZA_KROTKIE);
        if (password.length() > max) out.add(Problem.ZA_DLUGIE);

        boolean upper = false, lower = false, digit = false, special = false, space = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isWhitespace(c)) space = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else special = true;
        }
        if (!upper) out.add(Problem.BRAK_DUZEJ);
        if (!lower) out.add(Problem.BRAK_MALEJ);
        if (!digit) out.add(Problem.BRAK_CYFRY);
        if (!special) out.add(Problem.BRAK_ZNAKU);
        if (space) out.add(Problem.SPACJE);

        String low = password.toLowerCase(Locale.ROOT);
        if (nick != null && nick.length() >= 3 && low.contains(nick.toLowerCase(Locale.ROOT))) {
            out.add(Problem.ZAWIERA_NICK);
        }
        if (isCommon(low)) out.add(Problem.POPULARNE);
        if (hasRepeats(password)) out.add(Problem.POWTORZENIA);
        if (hasSequence(low, 4)) out.add(Problem.SEKWENCJA);
        return out;
    }

    private static boolean isCommon(String lower) {
        if (COMMON_EXACT.contains(lower)) return true;
        String normalized = normalize(lower);
        for (String part : COMMON_PARTS) {
            if (lower.contains(part) || normalized.contains(part)) return true;
        }
        return false;
    }

    /** Sprowadza popularne podmiany ("leet") do liter, żeby P@ssw0rd też był wykryty. */
    private static String normalize(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toLowerCase(Locale.ROOT).toCharArray()) {
            sb.append(switch (c) {
                case '@', '4' -> 'a';
                case '0' -> 'o';
                case '3' -> 'e';
                case '$', '5' -> 's';
                case '7' -> 't';
                case '!', '1' -> 'i';
                default -> c;
            });
        }
        return sb.toString();
    }

    private static boolean hasRepeats(String s) {
        for (int i = 0; i + 2 < s.length(); i++) {
            if (s.charAt(i) == s.charAt(i + 1) && s.charAt(i) == s.charAt(i + 2)) return true;
        }
        return false;
    }

    private static boolean hasSequence(String lower, int n) {
        for (String seq : SEQUENCES) {
            String rev = new StringBuilder(seq).reverse().toString();
            for (int i = 0; i + n <= seq.length(); i++) {
                if (lower.contains(seq.substring(i, i + n)) || lower.contains(rev.substring(i, i + n))) {
                    return true;
                }
            }
        }
        return false;
    }
}
