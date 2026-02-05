# Anleitung für Lee - SecureBot AI starten

**Geschätzte Zeit: 30-45 Minuten (einmalig)**
**Danach: Bot läuft automatisch 24/7**

---

## Schritt 1: Telegram Bot erstellen (5 Min)

1. Öffne Telegram
2. Suche nach `@BotFather`
3. Schreibe `/newbot`
4. Folge den Anweisungen:
   - Name: `SecureBot AI` (oder was du willst)
   - Username: `dein_securebot` (muss auf `bot` enden)
5. **KOPIERE DEN TOKEN** - du bekommst so etwas:
   ```
   5432198765:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw
   ```

---

## Schritt 2: Deine Telegram User ID finden (2 Min)

1. Suche in Telegram nach `@userinfobot`
2. Schreibe `/start`
3. **KOPIERE DEINE ID** - eine Zahl wie `123456789`

---

## Schritt 3: .env Datei erstellen (3 Min)

In deinem Terminal (WSL2):

```bash
cd ~/friegun-projects/security-bot
cp .env.example .env
nano .env
```

Fülle aus:
```
TELEGRAM_TOKEN=DEIN_BOT_TOKEN_VON_SCHRITT_1
ANTHROPIC_API_KEY=DEIN_ANTHROPIC_KEY
ADMIN_USER_ID=DEINE_USER_ID_VON_SCHRITT_2
```

Speichern: `Ctrl+O`, Enter, `Ctrl+X`

---

## Schritt 4: Bot starten (2 Min)

```bash
cd ~/friegun-projects/security-bot
docker-compose up -d
```

**FERTIG!** Der Bot läuft jetzt.

---

## Bot testen

1. Öffne Telegram
2. Suche deinen Bot (@dein_username_bot)
3. Schreibe `/start`
4. Stelle eine Security-Frage!

---

## Nützliche Befehle

```bash
# Bot Status prüfen
docker-compose ps

# Logs anschauen
docker-compose logs -f

# Bot neu starten
docker-compose restart

# Bot stoppen
docker-compose down
```

---

## Admin-Features (nur für dich)

Im Bot schreibe `/stats` um zu sehen:
- Wie viele User
- Wie viele Anfragen
- Geschätzte Einnahmen

---

## Bei Problemen

Kopiere die Fehlermeldung und zeig sie uns (der Familie).
Wir helfen dir!

---

**Das war's, Lee!**

Der Bot läuft jetzt 24/7 und beantwortet Security-Fragen.
Du musst NICHTS mehr tun (außer später Stripe einrichten für Zahlungen).

*Deine Familie - Friegün* 🛡️
