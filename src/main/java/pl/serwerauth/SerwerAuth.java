package pl.serwerauth;

import org.apache.logging.log4j.LogManager;
import org.bukkit.Bukkit;
import org.bukkit.command.PluginCommand;
import org.bukkit.entity.Player;
import org.bukkit.plugin.PluginManager;
import org.bukkit.plugin.java.JavaPlugin;
import pl.serwerauth.auth.AuthManager;
import pl.serwerauth.captcha.CaptchaMap;
import pl.serwerauth.command.AuthCommands;
import pl.serwerauth.config.Messages;
import pl.serwerauth.listener.ConnectionListener;
import pl.serwerauth.listener.ProtectionListener;
import pl.serwerauth.premium.PremiumService;
import pl.serwerauth.storage.Database;
import pl.serwerauth.util.PasswordLogFilter;

import java.io.File;
import java.sql.SQLException;
import java.util.List;
import java.util.logging.Level;

public final class SerwerAuth extends JavaPlugin {

    private static SerwerAuth instance;

    private Messages messages;
    private Database database;
    private AuthManager auth;
    private PremiumService premium;

    public static SerwerAuth getInstance() {
        return instance;
    }

    public AuthManager auth() {
        return auth;
    }

    public PremiumService premium() {
        return premium;
    }

    @Override
    public void onEnable() {
        instance = this;
        saveDefaultConfig();
        messages = new Messages(this);

        try {
            database = new Database(new File(getDataFolder(), "konta.db"));
        } catch (SQLException e) {
            getLogger().log(Level.SEVERE, "Nie można otworzyć bazy danych — wyłączam plugin.", e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        premium = new PremiumService(this);
        // kanał do modułu Velocity (lista nicków wymuszających tryb online)
        getServer().getMessenger().registerOutgoingPluginChannel(this, PremiumService.CHANNEL);
        CaptchaMap captchaMap = new CaptchaMap(this);
        auth = new AuthManager(this, database, messages, premium, captchaMap);

        PluginManager pm = getServer().getPluginManager();
        pm.registerEvents(new ConnectionListener(this, auth, database, messages), this);
        pm.registerEvents(new ProtectionListener(this, auth, messages), this);

        AuthCommands commands = new AuthCommands(this, auth, database, messages, premium);
        for (String name : List.of("login", "register", "changepassword", "unregister", "premium", "auth")) {
            PluginCommand pc = getCommand(name);
            if (pc != null) {
                pc.setExecutor(commands);
                pc.setTabCompleter(commands);
            }
        }

        installLogFilter();
        Bukkit.getScheduler().runTaskTimerAsynchronously(this, () -> auth.cleanup(), 12_000L, 12_000L);

        // po /reload gracze już online muszą przejść weryfikację od nowa
        for (Player p : Bukkit.getOnlinePlayers()) {
            auth.onJoin(p);
        }
        getLogger().info("SerwerAuth włączony.");
    }

    @Override
    public void onDisable() {
        getServer().getMessenger().unregisterOutgoingPluginChannel(this);
        if (auth != null) auth.shutdown();
        if (database != null) database.close();
        instance = null;
    }

    public void reloadAll() {
        reloadConfig();
        messages.reload();
        auth.reloadSettings();
    }

    /** Ukrywa w logach serwera komendy z hasłami. Gdy log4j-core jest niedostępny, pomija bez błędu. */
    private void installLogFilter() {
        try {
            org.apache.logging.log4j.Logger root = LogManager.getRootLogger();
            if (root instanceof org.apache.logging.log4j.core.Logger core) {
                core.addFilter(new PasswordLogFilter());
            }
        } catch (Throwable t) {
            getLogger().warning("Nie udało się zainstalować filtra haseł w logach: " + t);
        }
    }
}
