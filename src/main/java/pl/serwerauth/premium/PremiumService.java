package pl.serwerauth.premium;

import org.bukkit.entity.Player;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.storage.Account;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Konta premium.
 *
 * Weryfikacja: konto jest premium, gdy ma flagę premium i zapisany UUID z Mojang, a UUID aktualnie
 * łączącego się gracza jest IDENTYCZNY. Serwer offline wylicza UUID sam z nicku, więc nie da się
 * go podrobić; prawdziwy UUID z Mojang pojawia się tylko, gdy proxy (moduł Velocity) lub serwer
 * w trybie online potwierdził konto kryptograficznie.
 */
public final class PremiumService {

    /** Kanał komunikacji z modułem Velocity (lista nicków wymuszających tryb online). */
    public static final String CHANNEL = "serwerauth:premium";

    private record Cached(Optional<UUID> uuid, long at) {
    }

    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_]{3,16}$");
    private static final Pattern ID = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-fA-F]{32})\"");

    private final SerwerAuth plugin;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    public PremiumService(SerwerAuth plugin) {
        this.plugin = plugin;
    }

    public boolean enabled() {
        return plugin.getConfig().getBoolean("premium.wlaczone", true);
    }

    /** Czy to połączenie jest potwierdzonym kontem premium tego właściciela. */
    public boolean isVerified(Account account, Player player) {
        return enabled()
                && account != null
                && account.premium()
                && account.premiumUuid() != null
                && account.premiumUuid().equalsIgnoreCase(player.getUniqueId().toString());
    }

    /**
     * Informuje proxy (moduł Velocity), że nick ma wymuszać tryb online ("add") albo nie ("remove").
     * Bez modułu Velocity wiadomość po cichu nie jest wysyłana. Nick bierze proxy z połączenia, nie z treści.
     */
    public void syncProxy(Player player, boolean add) {
        if (!enabled()) return;
        try {
            player.sendPluginMessage(plugin, CHANNEL, (add ? "add" : "remove").getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            plugin.getLogger().fine("Nie wysłano wiadomości do proxy: " + e.getMessage());
        }
    }

    /** UUID konta premium o danym nicku lub puste, jeśli takiego konta nie ma. */
    public CompletableFuture<Optional<UUID>> lookup(String name) {
        if (!NAME.matcher(name).matches()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        String key = name.toLowerCase(Locale.ROOT);
        long ttl = plugin.getConfig().getLong("premium.cache-minuty", 10) * 60_000L;
        Cached c = cache.get(key);
        if (c != null && System.currentTimeMillis() - c.at() < ttl) {
            return CompletableFuture.completedFuture(c.uuid());
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://api.mojang.com/minecraft/profile/lookup/name/" + name))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .GET().build();
        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            Optional<UUID> result;
            if (resp.statusCode() == 200) {
                Matcher m = ID.matcher(resp.body());
                result = m.find() ? Optional.of(parse(m.group(1))) : Optional.empty();
            } else if (resp.statusCode() == 404 || resp.statusCode() == 204) {
                result = Optional.empty();
            } else {
                throw new IllegalStateException("API Mojang zwróciło HTTP " + resp.statusCode());
            }
            cache.put(key, new Cached(result, System.currentTimeMillis()));
            return result;
        });
    }

    private static UUID parse(String hex) {
        return UUID.fromString(hex.replaceFirst("(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                "$1-$2-$3-$4-$5"));
    }
}
