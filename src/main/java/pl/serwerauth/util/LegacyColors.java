package pl.serwerauth.util;

import java.util.Map;

/**
 * Zamienia kody kolorów w stylu &a, &6, &l na tagi MiniMessage, dzięki czemu w messages.yml
 * można pisać klasycznie (&fZalogowano z konta &6&lPREMIUM). Kody kolorów zerują formatowanie jak w grze.
 */
public final class LegacyColors {

    private static final Map<Character, String> CODES = Map.ofEntries(
            Map.entry('0', "<reset><black>"),
            Map.entry('1', "<reset><dark_blue>"),
            Map.entry('2', "<reset><dark_green>"),
            Map.entry('3', "<reset><dark_aqua>"),
            Map.entry('4', "<reset><dark_red>"),
            Map.entry('5', "<reset><dark_purple>"),
            Map.entry('6', "<reset><gold>"),
            Map.entry('7', "<reset><gray>"),
            Map.entry('8', "<reset><dark_gray>"),
            Map.entry('9', "<reset><blue>"),
            Map.entry('a', "<reset><green>"),
            Map.entry('b', "<reset><aqua>"),
            Map.entry('c', "<reset><red>"),
            Map.entry('d', "<reset><light_purple>"),
            Map.entry('e', "<reset><yellow>"),
            Map.entry('f', "<reset><white>"),
            Map.entry('k', "<obfuscated>"),
            Map.entry('l', "<bold>"),
            Map.entry('m', "<strikethrough>"),
            Map.entry('n', "<underlined>"),
            Map.entry('o', "<italic>"),
            Map.entry('r', "<reset>"));

    private LegacyColors() {
    }

    public static String toMini(String input) {
        if (input == null || input.indexOf('&') < 0) return input;
        StringBuilder sb = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '&' && i + 1 < input.length()) {
                String tag = CODES.get(Character.toLowerCase(input.charAt(i + 1)));
                if (tag != null) {
                    sb.append(tag);
                    i++;
                    continue;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }
}
