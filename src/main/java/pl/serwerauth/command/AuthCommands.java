package pl.serwerauth.command;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.auth.AuthManager;
import pl.serwerauth.config.Messages;
import pl.serwerauth.premium.PremiumService;
import pl.serwerauth.storage.Database;
import pl.serwerauth.util.TimeFormat;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

import static pl.serwerauth.config.Messages.ph;

public final class AuthCommands implements CommandExecutor, TabCompleter {

    private final SerwerAuth plugin;
    private final AuthManager auth;
    private final Database db;
    private final Messages msg;
    private final PremiumService premium;

    public AuthCommands(SerwerAuth plugin, AuthManager auth, Database db, Messages msg, PremiumService premium) {
        this.plugin = plugin;
        this.auth = auth;
        this.db = db;
        this.msg = msg;
        this.premium = premium;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        String name = cmd.getName().toLowerCase(Locale.ROOT);
        if (name.equals("auth")) {
            return admin(sender, args);
        }
        if (!(sender instanceof Player p)) {
            sender.sendMessage("Ta komenda jest tylko dla graczy.");
            return true;
        }
        switch (name) {
            case "login" -> auth.login(p, args);
            case "register" -> auth.register(p, args);
            case "changepassword" -> {
                if (args.length != 2) msg.send(p, "zmiana.uzycie");
                else auth.changePassword(p, args[0], args[1]);
            }
            case "unregister" -> {
                if (args.length != 1) msg.send(p, "usuwanie.uzycie");
                else auth.unregister(p, args[0]);
            }
            case "premium" -> premiumCommand(p, args);
            default -> {
            }
        }
        return true;
    }

    private void premiumCommand(Player p, String[] args) {
        if (!auth.isAuthenticated(p)) {
            msg.send(p, "login.nie-teraz");
            return;
        }
        if (!premium.enabled()) {
            msg.send(p, "premium.wylaczone");
            return;
        }
        String sub = args.length > 0 ? args[0].toLowerCase(Locale.ROOT) : "";
        if (sub.equals("wylacz")) {
            db.setPremium(p.getName(), false, null).whenComplete((v, err) -> auth.sync(() -> {
                if (err != null) {
                    msg.send(p, "blad");
                } else {
                    premium.syncProxy(p, false);
                    msg.send(p, "premium.wylaczono");
                }
            }));
            return;
        }
        if (!sub.equals("potwierdz")) {
            msg.send(p, "premium.ostrzezenie"); // najpierw ostrzeżenie — to jest nieodwracalne dla graczy bez premium
            return;
        }
        msg.send(p, "premium.sprawdzam");
        premium.lookup(p.getName()).thenCompose(opt -> {
            if (opt.isEmpty()) return CompletableFuture.completedFuture(Boolean.FALSE);
            return db.setPremium(p.getName(), true, opt.get().toString()).thenApply(v -> Boolean.TRUE);
        }).whenComplete((ok, err) -> auth.sync(() -> {
            if (err != null) {
                msg.send(p, "premium.blad");
            } else if (!ok) {
                msg.send(p, "premium.brak-konta", ph("nick", p.getName()));
            } else {
                premium.syncProxy(p, true);
                msg.send(p, "premium.wlaczono");
            }
        }));
    }

    private boolean admin(CommandSender s, String[] a) {
        if (!s.hasPermission("serwerauth.admin")) {
            msg.send(s, "admin.brak-uprawnien");
            return true;
        }
        if (a.length == 0) {
            msg.send(s, "admin.pomoc");
            return true;
        }
        switch (a[0].toLowerCase(Locale.ROOT)) {
            case "reload" -> {
                plugin.reloadAll();
                msg.send(s, "admin.przeladowano");
            }
            case "info" -> {
                if (a.length < 2) {
                    msg.send(s, "admin.pomoc");
                    return true;
                }
                db.find(a[1]).whenComplete((opt, err) -> auth.sync(() -> {
                    if (err != null) {
                        msg.send(s, "blad");
                    } else if (opt.isEmpty()) {
                        msg.send(s, "admin.brak-konta");
                    } else {
                        var acc = opt.get();
                        msg.send(s, "admin.info",
                                ph("nick", acc.name()), ph("premium", acc.premium() ? "tak" : "nie"),
                                ph("data-rej", TimeFormat.date(acc.registeredAt())), ph("ip-rej", acc.regIp()),
                                ph("data-log", TimeFormat.date(acc.lastLogin())), ph("ip-log", acc.lastIp()));
                    }
                }));
            }
            case "usun" -> {
                if (a.length < 2) {
                    msg.send(s, "admin.pomoc");
                    return true;
                }
                String nick = a[1];
                db.delete(nick).whenComplete((deleted, err) -> auth.sync(() -> {
                    if (err != null) {
                        msg.send(s, "blad");
                    } else if (!deleted) {
                        msg.send(s, "admin.brak-konta");
                    } else {
                        auth.forgetSession(nick);
                        msg.send(s, "admin.usunieto", ph("nick", nick));
                        Player online = Bukkit.getPlayerExact(nick);
                        if (online != null) online.kick(msg.plain("kick.konto-usuniete"));
                    }
                }));
            }
            case "odblokuj" -> {
                if (a.length < 2) {
                    msg.send(s, "admin.pomoc");
                    return true;
                }
                auth.unlock(a[1]);
                msg.send(s, "admin.odblokowano", ph("cel", a[1]));
            }
            case "premiumoff" -> {
                if (a.length < 2) {
                    msg.send(s, "admin.pomoc");
                    return true;
                }
                String nick = a[1];
                db.find(nick).thenCompose(opt -> opt.isEmpty()
                        ? CompletableFuture.completedFuture(Boolean.FALSE)
                        : db.setPremium(nick, false, null).thenApply(v -> Boolean.TRUE)
                ).whenComplete((ok, err) -> auth.sync(() -> {
                    if (err != null) msg.send(s, "blad");
                    else if (!ok) msg.send(s, "admin.brak-konta");
                    else msg.send(s, "admin.premiumoff", ph("nick", nick));
                }));
            }
            default -> msg.send(s, "admin.pomoc");
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command cmd, String label, String[] args) {
        String name = cmd.getName().toLowerCase(Locale.ROOT);
        if (name.equals("auth") && sender.hasPermission("serwerauth.admin")) {
            if (args.length == 1) return filter(List.of("reload", "info", "usun", "odblokuj", "premiumoff"), args[0]);
            if (args.length == 2 && !args[0].equalsIgnoreCase("reload")) return null; // nicki graczy
        }
        if (name.equals("premium") && args.length == 1) return filter(List.of("potwierdz", "wylacz"), args[0]);
        return List.of();
    }

    private static List<String> filter(List<String> options, String prefix) {
        return options.stream().filter(o -> o.startsWith(prefix.toLowerCase(Locale.ROOT))).toList();
    }
}
