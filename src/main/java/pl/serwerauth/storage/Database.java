package pl.serwerauth.storage;

import pl.serwerauth.security.AttemptLimiter;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** SQLite (sterownik jest wbudowany w Paper). Wszystkie operacje idą przez jeden wątek, poza głównym wątkiem serwera. */
public final class Database implements AutoCloseable {

    @FunctionalInterface
    private interface SqlTask<T> {
        T run() throws SQLException;
    }

    private static final long LIMIT_RETENTION_MS = 24L * 3_600_000L;

    private final Connection conn;
    private final ExecutorService exec;

    public Database(File file) throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("Brak sterownika SQLite na serwerze", e);
        }
        File parent = file.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        conn = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
        try (Statement s = conn.createStatement()) {
            s.execute("PRAGMA journal_mode=WAL");
            s.execute("PRAGMA busy_timeout=5000");
            s.execute("CREATE TABLE IF NOT EXISTS accounts ("
                    + "name_lower TEXT PRIMARY KEY,"
                    + "name TEXT NOT NULL,"
                    + "hash TEXT NOT NULL,"
                    + "premium INTEGER NOT NULL DEFAULT 0,"
                    + "premium_uuid TEXT,"
                    + "reg_ip TEXT,"
                    + "last_ip TEXT,"
                    + "registered_at INTEGER NOT NULL,"
                    + "last_login INTEGER NOT NULL DEFAULT 0)");
            s.execute("CREATE INDEX IF NOT EXISTS idx_accounts_reg_ip ON accounts(reg_ip)");
            s.execute("CREATE TABLE IF NOT EXISTS limits ("
                    + "k TEXT PRIMARY KEY,"
                    + "fails INTEGER NOT NULL,"
                    + "lockouts INTEGER NOT NULL,"
                    + "locked_until INTEGER NOT NULL,"
                    + "last_fail INTEGER NOT NULL)");
        }
        exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "SerwerAuth-DB");
            t.setDaemon(true);
            return t;
        });
    }

    private <T> CompletableFuture<T> run(SqlTask<T> task) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return task.run();
            } catch (SQLException e) {
                throw new CompletionException(e);
            }
        }, exec);
    }

    private static String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------ konta

    public CompletableFuture<Optional<Account>> find(String name) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT name, hash, premium, premium_uuid, reg_ip, last_ip, registered_at, last_login "
                            + "FROM accounts WHERE name_lower = ?")) {
                ps.setString(1, key(name));
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return Optional.<Account>empty();
                    return Optional.of(new Account(
                            rs.getString("name"), rs.getString("hash"), rs.getInt("premium") == 1,
                            rs.getString("premium_uuid"), rs.getString("reg_ip"), rs.getString("last_ip"),
                            rs.getLong("registered_at"), rs.getLong("last_login")));
                }
            }
        });
    }

    public CompletableFuture<Void> create(Account a) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO accounts (name_lower, name, hash, premium, premium_uuid, reg_ip, last_ip, registered_at, last_login) "
                            + "VALUES (?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, key(a.name()));
                ps.setString(2, a.name());
                ps.setString(3, a.hash());
                ps.setInt(4, a.premium() ? 1 : 0);
                ps.setString(5, a.premiumUuid());
                ps.setString(6, a.regIp());
                ps.setString(7, a.lastIp());
                ps.setLong(8, a.registeredAt());
                ps.setLong(9, a.lastLogin());
                ps.executeUpdate();
            }
            return null;
        });
    }

    public CompletableFuture<Void> updateHash(String name, String hash) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET hash = ? WHERE name_lower = ?")) {
                ps.setString(1, hash);
                ps.setString(2, key(name));
                ps.executeUpdate();
            }
            return null;
        });
    }

    public CompletableFuture<Void> touchLogin(String name, String ip) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE accounts SET last_ip = ?, last_login = ? WHERE name_lower = ?")) {
                ps.setString(1, ip);
                ps.setLong(2, System.currentTimeMillis());
                ps.setString(3, key(name));
                ps.executeUpdate();
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> delete(String name) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM accounts WHERE name_lower = ?")) {
                ps.setString(1, key(name));
                return ps.executeUpdate() > 0;
            }
        });
    }

    public CompletableFuture<Void> setPremium(String name, boolean premium, String uuid) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE accounts SET premium = ?, premium_uuid = ? WHERE name_lower = ?")) {
                ps.setInt(1, premium ? 1 : 0);
                ps.setString(2, uuid);
                ps.setString(3, key(name));
                ps.executeUpdate();
            }
            return null;
        });
    }

    public CompletableFuture<Integer> countByIp(String ip) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM accounts WHERE reg_ip = ?")) {
                ps.setString(1, ip);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    // ------------------------------------------------------------------ trwałe blokady

    public CompletableFuture<Void> saveLimit(String key, AttemptLimiter.State s) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT OR REPLACE INTO limits (k, fails, lockouts, locked_until, last_fail) VALUES (?,?,?,?,?)")) {
                ps.setString(1, key);
                ps.setInt(2, s.fails());
                ps.setInt(3, s.lockouts());
                ps.setLong(4, s.lockedUntil());
                ps.setLong(5, s.lastFail());
                ps.executeUpdate();
            }
            return null;
        });
    }

    public CompletableFuture<Void> removeLimit(String key) {
        return run(() -> {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM limits WHERE k = ?")) {
                ps.setString(1, key);
                ps.executeUpdate();
            }
            return null;
        });
    }

    /** Wczytuje zapisane blokady (i kasuje wpisy starsze niż 24 h). */
    public CompletableFuture<Map<String, AttemptLimiter.State>> loadLimits() {
        return run(() -> {
            long cutoff = System.currentTimeMillis() - LIMIT_RETENTION_MS;
            try (PreparedStatement del = conn.prepareStatement("DELETE FROM limits WHERE MAX(last_fail, locked_until) <= ?")) {
                del.setLong(1, cutoff);
                del.executeUpdate();
            }
            Map<String, AttemptLimiter.State> out = new HashMap<>();
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT k, fails, lockouts, locked_until, last_fail FROM limits")) {
                while (rs.next()) {
                    out.put(rs.getString("k"), new AttemptLimiter.State(
                            rs.getInt("fails"), rs.getInt("lockouts"), rs.getLong("locked_until"), rs.getLong("last_fail")));
                }
            }
            return out;
        });
    }

    @Override
    public void close() {
        exec.shutdown();
        try {
            exec.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            conn.close();
        } catch (SQLException ignored) {
        }
    }
}
