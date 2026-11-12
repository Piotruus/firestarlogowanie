package pl.serwerauth.storage;

public record Account(String name, String hash, boolean premium, String premiumUuid,
                      String regIp, String lastIp, long registeredAt, long lastLogin) {

    public Account withHash(String newHash) {
        return new Account(name, newHash, premium, premiumUuid, regIp, lastIp, registeredAt, lastLogin);
    }
}
