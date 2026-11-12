package pl.serwerauth.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ConsoleCommandSource;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Moduł proxy do SerwerAuth.
 *
 * Nicki z listy premium są wpuszczane WYŁĄCZNIE w trybie online (Mojang sprawdza konto kryptograficznie),
 * pozostałe w trybie offline. Backend (Paper) dostaje wtedy prawdziwy UUID z Mojang i rozpoznaje premium.
 * Lista jest uzupełniana przez serwer Paper (wiadomość na kanale serwerauth:premium od zalogowanego gracza)
 * oraz ręcznie komendą konsoli /authpremium.
 */
@Plugin(id = "serwerauth", name = "SerwerAuth", version = "1.0.0", authors = {"SerwerAuth"})
public final class SerwerAuthVelocity {

    private static final MinecraftChannelIdentifier CHANNEL = MinecraftChannelIdentifier.create("serwerauth", "premium");

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path file;
    private final Set<String> premium = ConcurrentHashMap.newKeySet();

    @Inject
    public SerwerAuthVelocity(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxy = proxy;
        this.logger = logger;
        this.file = dataDirectory.resolve("premium.txt");
    }

    @Subscribe
    public void onInit(ProxyInitializeEvent event) {
        load();
        proxy.getChannelRegistrar().register(CHANNEL);

        CommandMeta meta = proxy.getCommandManager().metaBuilder("authpremium").plugin(this).build();
        proxy.getCommandManager().register(meta, new SimpleCommand() {
            @Override
            public void execute(Invocation invocation) {
                handleCommand(invocation);
            }

            @Override
            public boolean hasPermission(Invocation invocation) {
                return invocation.source() instanceof ConsoleCommandSource; // tylko konsola proxy
            }
        });
        logger.info("SerwerAuth-Velocity: wczytano {} nicków premium.", premium.size());
    }

    /** Premium → tryb online (weryfikuje Mojang); reszta → tryb offline. */
    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        if (premium.contains(event.getUsername().toLowerCase(Locale.ROOT))) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
        } else {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
        }
    }

    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {
        if (!CHANNEL.equals(event.getIdentifier())) return;
        // nigdy nie przekazuj tej wiadomości dalej (ani do klienta, ani do innych serwerów)
        event.setResult(PluginMessageEvent.ForwardResult.handled());
        // wiarygodne są tylko wiadomości od serwera backendowego, nie od klienta
        if (!(event.getSource() instanceof ServerConnection connection)) return;

        String command = new String(event.getData(), StandardCharsets.UTF_8).trim();
        String name = connection.getPlayer().getUsername().toLowerCase(Locale.ROOT); // nick z połączenia, nie z treści
        if (command.equals("add")) {
            if (premium.add(name)) {
                save();
                logger.info("Premium: dodano {}", name);
            }
        } else if (command.equals("remove")) {
            if (premium.remove(name)) {
                save();
                logger.info("Premium: usunięto {}", name);
            }
        }
    }

    private void handleCommand(SimpleCommand.Invocation inv) {
        if (!(inv.source() instanceof ConsoleCommandSource)) return; // dodatkowe zabezpieczenie: tylko konsola
        String[] a = inv.arguments();
        if (a.length == 1 && a[0].equalsIgnoreCase("list")) {
            List<String> sorted = new ArrayList<>(premium);
            Collections.sort(sorted);
            inv.source().sendMessage(Component.text("Premium (" + sorted.size() + "): " + String.join(", ", sorted)));
        } else if (a.length == 2 && a[0].equalsIgnoreCase("add")) {
            premium.add(a[1].toLowerCase(Locale.ROOT));
            save();
            inv.source().sendMessage(Component.text("Dodano: " + a[1]));
        } else if (a.length == 2 && a[0].equalsIgnoreCase("remove")) {
            boolean removed = premium.remove(a[1].toLowerCase(Locale.ROOT));
            save();
            inv.source().sendMessage(Component.text(removed ? "Usunięto: " + a[1] : "Nie było takiego nicku: " + a[1]));
        } else {
            inv.source().sendMessage(Component.text("Użycie: authpremium <add|remove> <nick> | authpremium list"));
        }
    }

    private void load() {
        try {
            Files.createDirectories(file.getParent());
            if (Files.exists(file)) {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    String n = line.trim().toLowerCase(Locale.ROOT);
                    if (!n.isEmpty()) premium.add(n);
                }
            }
        } catch (IOException e) {
            logger.error("Nie można wczytać premium.txt", e);
        }
    }

    private synchronized void save() {
        try {
            Files.createDirectories(file.getParent());
            List<String> sorted = new ArrayList<>(premium);
            Collections.sort(sorted);
            Files.write(file, sorted, StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error("Nie można zapisać premium.txt", e);
        }
    }
}
