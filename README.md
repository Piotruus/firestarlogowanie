# SerwerAuth — logowanie dla Paper 1.21.x

Plugin logowania i rejestracji: captcha, weryfikacja ruchu, silne hasła, trwałe blokady, tryb ataku i konta premium.
Wiadomości po polsku, kolory kodami `&`.

Repozytorium ma dwa projekty:

| Folder | Co to | Gdzie wrzucić |
|---|---|---|
| `/` (główny) | plugin dla **Paper** (`SerwerAuth-1.0.0.jar`) | `plugins/` serwera Paper (lobby) |
| `velocity/` | moduł dla **Velocity** (`SerwerAuth-Velocity-1.0.0.jar`) | `plugins/` proxy — **potrzebny tylko dla premium** |

## Budowanie

GitHub buduje oba pliki sam (`.github/workflows/build.yml`): zakładka **Actions → ostatni przebieg → Artifacts**.
Lokalnie: `mvn clean package` oraz `mvn -f velocity/pom.xml clean package` (Java 21).

## Przebieg wejścia gracza

1. Gracz wchodzi, ma **60 sekund** (`czas-na-zalogowanie`). Do skutku co kilka sekund dostaje na czacie:
   - nowy gracz: `&a/register (hasło) (hasło) (captcha)`
   - zarejestrowany: `&6/login (hasło)`
2. **Rejestracja jedną komendą:** `/register (hasło) (hasło) (captcha)`. Kod captcha jest na **mapie w ręce** gracza. Po sukcesie: `&aRejestracja przebiegła pomyślnie`.
   Kolejność kontroli: hasła zgodne → polityka haseł → captcha → limit kont → dopiero potem kosztowne haszowanie.
3. **Logowanie:** `/login (hasło)`. Captcha przy logowaniu jest opcjonalna (`captcha.przy-logowaniu: true` → `/login (hasło) (captcha)`).
4. **Weryfikacja ruchu** („Weryfikacja pozycji! Zacznij się poruszać! (1/5)”): 5 kroków, ruch kamerą i **zmiana kierunku marszu** (bot idący prosto odpada). Teleporty się nie liczą, jest limit strefy i czasu.
5. Dopiero wtedy gracz jest wolny, a na czacie pojawia się „dołączył do gry”.

Do końca weryfikacji zablokowane są: ruch, czat, komendy (poza logowaniem), interakcje, ekwipunek, obrażenia.

## Hasła i zabezpieczenia

- **PBKDF2-HMAC-SHA256**, 210 000 iteracji, losowa sól, porównanie w stałym czasie, automatyczny rehash po zmianie konfiguracji.
- Polityka haseł: min. 10 znaków, wielka i mała litera, cyfra, znak specjalny, bez spacji, bez nicku, bez popularnych haseł (także „leet”, np. `P@ssw0rd`), bez `aaa` i ciągów `1234`/`abcd`/`qwer`.
- **Trwałe blokady:** po 5 błędnych hasłach blokada 2 min, potem 4, 8… maks. 1 h — osobno dla nicku i IP. **Zapisane w bazie, przeżywają restart serwera** i `/auth reload`. Zdjąć je można `/auth odblokuj (nick lub IP)`.
- **Tryb ataku** (włącza się sam przy lawinie połączeń, domyślnie 25 prób / 10 s): zaostrzony limit połączeń z IP, nowe nicki bez konta są odrzucane (boty nie założą masowo kont), sesje są ignorowane, admini dostają alert. Gracze z kontem wchodzą normalnie. Uwaga: po restarcie serwera, gdy wszyscy wracają naraz, tryb może się włączyć na chwilę — próg zmienisz w `config.yml`.
- Limit połączeń na IP/minutę, limit kont na IP, walidacja nicku, wymuszona ta sama wielkość liter nicku.
- Hasła nie trafiają do logów konsoli (filtr log4j).
- Baza SQLite (`plugins/SerwerAuth/konta.db`), operacje poza głównym wątkiem.
- Ekwipunek gracza jest zabezpieczony kopią w pliku na czas wyświetlania mapy captcha (także po awarii serwera).

## Komendy

| Komenda | Opis |
|---|---|
| `/register (hasło) (hasło) (captcha)` (`/reg`) | rejestracja |
| `/login (hasło)` (`/l`) | logowanie |
| `/changepassword (stare) (nowe)` (**`/zmienhaslo`**) | zmiana hasła (wymaga starego, unieważnia zapamiętaną sesję) |
| `/unregister (hasło)` | usunięcie konta |
| `/premium` → `/premium potwierdz` / `/premium wylacz` | tryb konta premium |
| `/auth reload` · `info (nick)` · `usun (nick)` · `odblokuj (nick/IP)` · `premiumoff (nick)` | administracja (`serwerauth.admin`) |

## Konta premium — jak to działa naprawdę

Prawdziwe „wejście premium bez hasła” wymaga, by **Mojang potwierdził konto** (szyfrowany handshake). Zwykły serwer Paper w trybie offline tego nie potrafi, więc robi to **moduł Velocity**:

1. Gracz wpisuje `/premium`, czyta ostrzeżenie i potwierdza `/premium potwierdz`. Plugin sprawdza w API Mojang, czy taki nick istnieje, i zapisuje UUID konta premium.
2. Plugin mówi proxy, że ten nick ma być wpuszczany **tylko w trybie online**.
3. Od następnego wejścia Mojang sprawdza konto na proxy; Paper dostaje prawdziwy UUID, porównuje go z zapisanym i pisze na czacie: `&fZalogowano z konta &6&lPREMIUM`. Captcha, hasło i ruch są pomijane (ruch można włączyć: `premium.weryfikacja-ruchu`).
4. Kto nie ma oficjalnego konta, nie wejdzie na ten nick w ogóle — Mojang odrzuci logowanie.

Podrobić tego nie da się: serwer offline liczy UUID z nicku, więc cracked-klient nigdy nie dostanie UUID z Mojang.

**Konfiguracja (wymagana):**

- `velocity.toml`: `player-info-forwarding-mode = "modern"` (z sekretem w `forwarding.secret`); `online-mode` może zostać `false` — moduł decyduje per gracz.
- Paper `config/paper-global.yml`: `proxies.velocity: enabled: true, online-mode: true, secret: '<ten sam sekret>'`; `server.properties`: `online-mode=false`.
- Serwery Paper muszą być dostępne **tylko przez proxy** (firewall) — inaczej ktoś podszyje się pod UUID.
- **Nie używaj razem z FastLogin** — oba pluginy rozstrzygałyby tryb online.
- Konsola proxy: `authpremium list | add (nick) | remove (nick)`. Lista jest w `plugins/serwerauth/premium.txt` na proxy.
- Bez modułu Velocity `/premium` nic nie wzmacnia: konta logują się hasłem. `premium.blokuj-nieweryfikowane: true` wpuszcza konta premium tylko z oficjalnego launchera (włącz dopiero po uruchomieniu modułu).
- Standalone Paper z `online-mode=true` też działa (wszyscy mają UUID z Mojang), ale wtedy nie wejdą gracze bez premium.

## Konfiguracja

`plugins/SerwerAuth/config.yml` (opisane komentarzami) i `messages.yml` (kody `&` oraz MiniMessage). Zmiany: `/auth reload`.

## Czego plugin nie robi

- Serwer offline nie szyfruje połączenia, więc `/login` leci jawnie przez sieć (dotyczy każdego takiego serwera).
- Captcha, weryfikacja ruchu i tryb ataku zatrzymują proste i średnio zaawansowane boty. Bot z OCR i symulacją ruchu z losowymi zakrętami może je przejść, a atak wolumetryczny (DDoS) wymaga ochrony na poziomie sieci/hostingu.
- Brak resetu hasła przez e-mail: admin usuwa konto (`/auth usun`), a gracz rejestruje się od nowa — rób to, gdy gracz jest online.
- Brak 2FA.
