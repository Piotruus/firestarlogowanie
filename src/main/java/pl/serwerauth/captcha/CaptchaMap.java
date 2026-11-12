package pl.serwerauth.captcha;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.PlayerInventory;
import org.bukkit.inventory.meta.MapMeta;
import org.bukkit.map.MapCanvas;
import org.bukkit.map.MapRenderer;
import org.bukkit.map.MapView;
import org.bukkit.persistence.PersistentDataType;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.security.CaptchaGenerator;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

/**
 * Captcha jako obrazek na mapie trzymanej w ręce.
 * - Jedna wspólna mapa (jedno ID) z rendererem kontekstowym: każdy gracz widzi własny obrazek.
 * - Przedmiot gracza, który zajmowałby slot mapy, jest zapisywany w pliku kopii i przywracany
 *   (także po awarii serwera, przy następnym wejściu).
 */
public final class CaptchaMap {

    private record Held(int slot, ItemStack saved, int prevHeld) {
    }

    private final SerwerAuth plugin;
    private final NamespacedKey markKey;
    private final File dataFile;
    private final File backupFile;
    private final ConcurrentHashMap<UUID, BufferedImage> images = new ConcurrentHashMap<>();
    private final Set<UUID> dirty = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<UUID, Held> held = new ConcurrentHashMap<>();
    private volatile MapView view;
    private volatile boolean renderFailed;

    public CaptchaMap(SerwerAuth plugin) {
        this.plugin = plugin;
        this.markKey = new NamespacedKey(plugin, "captcha");
        this.dataFile = new File(plugin.getDataFolder(), "data.yml");
        this.backupFile = new File(plugin.getDataFolder(), "kopia-ekwipunku.yml");
        initView();
        // rozgrzewka czcionek AWT poza głównym wątkiem
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            try {
                CaptchaGenerator.render("ABCDE");
            } catch (Throwable t) {
                renderFailed = true;
                plugin.getLogger().log(Level.WARNING,
                        "Nie można generować obrazków captcha (brak czcionek w JVM?) — używam trybu czatu.", t);
            }
        });
    }

    @SuppressWarnings("deprecation")
    private void initView() {
        try {
            YamlConfiguration data = YamlConfiguration.loadConfiguration(dataFile);
            int id = data.getInt("captcha-map-id", -1);
            MapView v = id >= 0 ? Bukkit.getMap(id) : null;
            if (v == null) {
                v = Bukkit.createMap(Bukkit.getWorlds().get(0));
                data.set("captcha-map-id", v.getId());
                data.save(dataFile);
            }
            v.setTrackingPosition(false);
            v.setUnlimitedTracking(false);
            for (MapRenderer r : new ArrayList<>(v.getRenderers())) {
                v.removeRenderer(r);
            }
            v.addRenderer(new Renderer());
            view = v;
        } catch (Exception e) {
            plugin.getLogger().log(Level.WARNING, "Nie udało się przygotować mapy captcha — używam trybu czatu.", e);
        }
    }

    public boolean available() {
        return view != null && !renderFailed;
    }

    /** Pokazuje graczowi nowy obrazek captcha. Zwraca false, gdy trzeba użyć trybu czatu. */
    public boolean show(Player p, String code) {
        if (!available()) return false;
        BufferedImage img;
        try {
            img = CaptchaGenerator.render(code);
        } catch (Throwable t) {
            renderFailed = true;
            plugin.getLogger().log(Level.WARNING, "Błąd generowania captcha — przełączam na tryb czatu.", t);
            return false;
        }
        UUID id = p.getUniqueId();
        images.put(id, img);
        dirty.add(id);

        PlayerInventory inv = p.getInventory();
        Held h = held.get(id);
        if (h == null) {
            int slot = firstEmptyHotbar(inv);
            if (slot < 0) slot = inv.getHeldItemSlot();
            ItemStack old = inv.getItem(slot);
            ItemStack saved = isEmpty(old) ? null : old.clone();
            if (saved != null) saveBackup(id, slot, saved);
            h = new Held(slot, saved, inv.getHeldItemSlot());
            held.put(id, h);
        }
        inv.setItem(h.slot(), createItem());
        inv.setHeldItemSlot(h.slot());
        p.sendMap(view);
        return true;
    }

    /** Usuwa mapę captcha i oddaje graczowi jego przedmiot. */
    public void hide(Player p) {
        UUID id = p.getUniqueId();
        images.remove(id);
        dirty.remove(id);
        Held h = held.remove(id);
        PlayerInventory inv = p.getInventory();
        removeMarked(inv);
        if (h != null) {
            inv.setItem(h.slot(), h.saved());
            inv.setHeldItemSlot(h.prevHeld());
            clearBackup(id);
        }
    }

    /** Wołane przy wejściu: sprzątanie po ewentualnej awarii (zostawiona mapa, zagubiony przedmiot). */
    public void recover(Player p) {
        UUID id = p.getUniqueId();
        PlayerInventory inv = p.getInventory();
        removeMarked(inv);
        YamlConfiguration b = YamlConfiguration.loadConfiguration(backupFile);
        String base = id.toString();
        if (!b.contains(base)) return;
        ItemStack item = b.getItemStack(base + ".item");
        int slot = b.getInt(base + ".slot", -1);
        if (item != null) {
            ItemStack current = slot >= 0 ? inv.getItem(slot) : null;
            if (slot >= 0 && isEmpty(current)) {
                inv.setItem(slot, item);
            } else {
                inv.addItem(item).values().forEach(rest -> p.getWorld().dropItemNaturally(p.getLocation(), rest));
            }
        }
        clearBackup(id);
    }

    private void removeMarked(PlayerInventory inv) {
        for (int i = 0; i < inv.getSize(); i++) {
            if (isCaptchaMap(inv.getItem(i))) {
                inv.setItem(i, null);
            }
        }
    }

    private boolean isCaptchaMap(ItemStack it) {
        if (it == null || it.getType() != Material.FILLED_MAP || !it.hasItemMeta()) return false;
        return it.getItemMeta().getPersistentDataContainer().has(markKey, PersistentDataType.BYTE);
    }

    private ItemStack createItem() {
        ItemStack item = new ItemStack(Material.FILLED_MAP);
        MapMeta meta = (MapMeta) item.getItemMeta();
        meta.setMapView(view);
        meta.displayName(Component.text("Kod weryfikacyjny", NamedTextColor.YELLOW)
                .decoration(TextDecoration.ITALIC, false));
        meta.getPersistentDataContainer().set(markKey, PersistentDataType.BYTE, (byte) 1);
        item.setItemMeta(meta);
        return item;
    }

    private static int firstEmptyHotbar(PlayerInventory inv) {
        for (int i = 0; i < 9; i++) {
            if (isEmpty(inv.getItem(i))) return i;
        }
        return -1;
    }

    private static boolean isEmpty(ItemStack it) {
        return it == null || it.getType().isAir();
    }

    private void saveBackup(UUID id, int slot, ItemStack item) {
        try {
            YamlConfiguration b = YamlConfiguration.loadConfiguration(backupFile);
            b.set(id + ".slot", slot);
            b.set(id + ".item", item);
            b.save(backupFile);
        } catch (IOException e) {
            plugin.getLogger().log(Level.WARNING, "Nie udało się zapisać kopii ekwipunku", e);
        }
    }

    private void clearBackup(UUID id) {
        if (!backupFile.exists()) return;
        try {
            YamlConfiguration b = YamlConfiguration.loadConfiguration(backupFile);
            if (b.contains(id.toString())) {
                b.set(id.toString(), null);
                b.save(backupFile);
            }
        } catch (IOException e) {
            plugin.getLogger().log(Level.WARNING, "Nie udało się wyczyścić kopii ekwipunku", e);
        }
    }

    /** Renderer kontekstowy: rysuje obrazek danego gracza tylko wtedy, gdy się zmienił. */
    private final class Renderer extends MapRenderer {
        Renderer() {
            super(true);
        }

        @Override
        public void render(MapView map, MapCanvas canvas, Player player) {
            UUID id = player.getUniqueId();
            if (!dirty.remove(id)) return;
            BufferedImage img = images.get(id);
            if (img != null) {
                canvas.drawImage(0, 0, img);
            }
        }
    }
}
