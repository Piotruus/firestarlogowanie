package pl.serwerauth.listener;

import net.kyori.adventure.text.Component;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.auth.AuthManager;
import pl.serwerauth.config.Messages;
import pl.serwerauth.storage.Account;
import pl.serwerauth.storage.Database;
import pl.serwerauth.util.TimeFormat;

import java.util.Optional;

import static pl.serwerauth.config.Messages.ph;

public final class ConnectionListener implements Listener {

    private final SerwerAuth plugin;
    private final AuthManager auth;
    private final Database db;
    private final Messages msg;

    public ConnectionListener(SerwerAuth plugin, AuthManager auth, Database db, Messages msg) {
        this.plugin = plugin;
        this.auth = auth;
        this.db = db;
        this.msg = msg;
    }

    /** Wstępne filtrowanie połączeń: nick, limity IP, tryb ataku, blokady, wielkość liter nicku. */
    @EventHandler(priority = EventPriority.HIGH)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        if (e.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        String name = e.getName();
        String ip = e.getAddress().getHostAddress();

        if (!auth.nickPattern().matcher(name).matches()) {
            deny(e, msg.plain("kick.nick"));
            return;
        }
        if (!auth.connectionAttempt(ip)) {
            deny(e, msg.plain("kick.polaczenia"));
            return;
        }
        long wait = auth.lockRemaining(ip, name);
        if (wait > 0) {
            deny(e, msg.plain("kick.zablokowano", ph("czas", TimeFormat.format(wait))));
            return;
        }
        try {
            Optional<Account> acc = db.find(name).join();
            if (acc.isPresent() && !acc.get().name().equals(name)) {
                deny(e, msg.plain("kick.zly-rozmiar", ph("nick", acc.get().name())));
                return;
            }
            if (acc.isEmpty() && auth.blockNewNicksNow()) {
                deny(e, msg.plain("kick.atak"));
            }
        } catch (Exception ex) {
            plugin.getLogger().warning("Błąd bazy przy sprawdzaniu nicku " + name + ": " + ex.getMessage());
            deny(e, msg.plain("kick.blad-bazy"));
        }
    }

    private static void deny(AsyncPlayerPreLoginEvent e, Component reason) {
        e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, reason);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent e) {
        if (plugin.getConfig().getBoolean("ukryj-komunikaty-dolaczenia", true)) {
            e.joinMessage(null);
        }
        auth.onJoin(e.getPlayer());
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        if (plugin.getConfig().getBoolean("ukryj-komunikaty-dolaczenia", true) && auth.isLocked(p)) {
            e.quitMessage(null);
        }
        auth.onQuit(p);
    }
}
