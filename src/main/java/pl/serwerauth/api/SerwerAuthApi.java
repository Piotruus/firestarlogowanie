package pl.serwerauth.api;

import org.bukkit.entity.Player;
import pl.serwerauth.SerwerAuth;

/** API dla innych pluginów. */
public final class SerwerAuthApi {

    private SerwerAuthApi() {
    }

    /** Czy gracz przeszedł pełną weryfikację (logowanie/rejestracja, captcha, ruch). */
    public static boolean isAuthenticated(Player player) {
        SerwerAuth plugin = SerwerAuth.getInstance();
        return plugin != null && plugin.auth() != null && plugin.auth().isAuthenticated(player);
    }
}
