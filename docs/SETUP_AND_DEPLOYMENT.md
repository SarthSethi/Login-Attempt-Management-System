# LAMS - Setup and Deployment

How I run the project on my laptop, how it is deployed on Render + Aiven, and how to fix the usual
problems.

## 1. What is needed

- JDK 21 (`java -version` must show 21)
- MySQL 8, or Docker Desktop to run MySQL in a container
- Git

Maven does not have to be installed. The project includes the Maven wrapper (`./mvnw`, on Windows
`mvnw.cmd`), which downloads the right Maven version the first time.

## 2. Running it locally

### Step 1 - the .env file

The app reads its settings from environment variables, and for local use from a `.env` file in the
project folder. `.env` is in `.gitignore`, so passwords never go to GitHub.

```bash
cp .env.example .env
```

Then edit `.env`. The important lines:

```text
DB_HOST=localhost
DB_PORT=3306
DB_NAME=login_monitoring_system
DB_USERNAME=lams_user
DB_PASSWORD=<choose a password>
ADMIN_EMAIL=<admin login email>
ADMIN_PASSWORD=<8+ characters with letters and digits>
PORT=8090
DISPLAY_TIMEZONE=Asia/Kolkata
```

### Step 2 - the database

Option A, local MySQL: the script creates the database and the user from the values in `.env`
(it asks for the MySQL root password):

```bash
./scripts/setup-local-mysql.sh
```

Or the same by hand as root:

```sql
CREATE DATABASE login_monitoring_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'lams_user'@'localhost' IDENTIFIED BY 'your-db-password';
GRANT ALL PRIVILEGES ON login_monitoring_system.* TO 'lams_user'@'localhost';
FLUSH PRIVILEGES;
```

Option B, Docker: `docker compose up -d` starts MySQL 8.4 with a saved volume and creates the database
and user from `.env`.

I do not create any tables myself. Hibernate creates all 8 tables on the first start.

### Step 3 - start the app

```bash
./mvnw spring-boot:run
```

Open `http://localhost:8090` (the PORT from `.env`). In the log I should see
`Started LoginMonitoringApplication` and `Administrator account created`. The admin logs in with
ADMIN_EMAIL / ADMIN_PASSWORD.

Health check: `http://localhost:8090/actuator/health` returns `{"status":"UP"}` when the database is
reachable.

To build a jar instead:

```bash
./mvnw clean package
java -jar target/login-monitoring-system.jar
```

### Step 4 - run the tests

```bash
./mvnw test
```

The tests use an in-memory H2 database and need neither MySQL nor internet. The result should be
`Tests run: 106, Failures: 0, Errors: 0`.

### Two IPs on one laptop

The rules are per IP. On my laptop `http://localhost:8090` (IPv6 `::1`) and `http://127.0.0.1:8090`
(IPv4) count as two different IPs, so I can be "attacker" in one tab and admin in the other. A phone on
the same Wi-Fi also works: open `http://<laptop IP>:8090` (find it with `ipconfig getifaddr en0` on Mac).

## 3. Settings

All settings have defaults in `src/main/resources/application.properties`. The ones I might change:

| Variable | Default | Meaning |
|---|---|---|
| MAX_FAILED_ATTEMPTS | 5 | Rule 1 failures for one account from one IP |
| MONITORING_WINDOW | 10m | rolling window |
| BLOCK_DURATION | 15m | first lock / block (use `2m` to show expiry live) |
| IP_MAX_ACCOUNTS | 4 | Rule 2 |
| IP_MAX_FAILURES | 10 | Rule 3 |
| ACCOUNT_MAX_FAILURES / ACCOUNT_MIN_IPS | 8 / 3 | Rule 4 |
| REPEAT_BLOCK_DURATIONS | 1h,24h | Rule 5 |
| TRUSTED_PROXIES | empty | proxy IP ranges allowed to set X-Forwarded-For (not needed on Render) |
| IP_LOOKUP_ENABLED / BREACH_CHECK_ENABLED | true | outside services |
| ATTEMPT_RETENTION | 180d | attempts older than this are deleted at night |
| DISPLAY_TIMEZONE | UTC | time zone on the pages |
| SESSION_COOKIE_SECURE | false | `true` when served over HTTPS |

After changing `.env` I restart the app.

## 4. Deployment on Render + Aiven

```text
Browser --HTTPS--> Cloudflare --> Render (Docker container, free) --SSL--> Aiven (MySQL, free)
```

I use Render for the app because it runs the `Dockerfile` for free with HTTPS, and Aiven for the
database because Render's free database is PostgreSQL only.

### Aiven (database)

1. Sign up at console.aiven.io, create a service, choose **MySQL** and the **Free** plan.
2. Wait until it says **Running**.
3. From the service Overview copy Host, Port, User (`avnadmin`) and Password.

No tables need to be created.

### Render (app)

1. Sign up at render.com with GitHub.
2. New -> **Blueprint** -> choose the repository. Render reads `render.yaml` (Docker, free plan,
   health check `/actuator/health`, `prod` profile, `DB_SSL_MODE=REQUIRED`, time zone).
3. Enter the values it asks for: `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD` from Aiven, and
   `ADMIN_EMAIL`, `ADMIN_PASSWORD`.
4. Deploy. The first build takes 5-10 minutes. Success in the logs:
   `The following 1 profile is active: "prod"`, `Started LoginMonitoringApplication`,
   `Administrator account created`.

After that every push to `main` deploys automatically.

### How the visitor IP works on Render

Render sets `RENDER=true` on every service. When the app sees it, `ClientIpResolver` reads the
visitor's IP from Cloudflare's `CF-Connecting-IP` header. Nothing has to be configured.

### Checks after deploying

1. `https://<app>.onrender.com/actuator/health` shows `"status":"UP"`.
2. Admin -> Overview -> **Connection Check**: "Your IP as seen by LAMS" is my public IP (compare with
   api.ipify.org) and "Found using" says `Header CF-Connecting-IP`.
3. An attempt from my phone shows a country and provider in the Attempt Log after a few seconds.
4. Registering with `Password123` is refused (breach check reachable).
5. 5 wrong passwords from the phone -> "paused" message; the laptop can still log in.

### Updating

Changes are merged into `main` on GitHub; Render rebuilds by itself. On startup Hibernate adds any new
tables or columns and keeps the existing data.

## 5. Free-plan behaviour

- The Render service sleeps after 15 minutes without visitors; the first request then takes about a
  minute. I open the site a few minutes before a demo.
- Render's free plan blocks outgoing SMTP, which is why alerts are shown in the app and not e-mailed.
- Aiven may power off a free service after a long time without use; it can be powered on again in the
  console.
- Render's free plan has 512 MB RAM; the Dockerfile's JVM flags keep the app at about 300 MB.

## 6. Troubleshooting

| Problem | Cause and fix |
|---|---|
| `Communications link failure` | wrong DB_HOST/DB_PORT, or the Aiven service is not Running |
| `Access denied for user` | wrong DB_PASSWORD |
| Error about `CREATE DATABASE` | set `DB_NAME=defaultdb` (Aiven's ready-made database) |
| `Public Key Retrieval is not allowed` (local MySQL) | use `DB_SSL_MODE=PREFERRED` |
| `ADMIN_PASSWORD must be 8-64 characters` | choose a password with letters and digits |
| Port already in use | set another PORT in `.env`, e.g. 8090 |
| Connection Check shows a `10.x.x.x` address and "Direct connection" on Render | the Cloudflare header did not arrive; check "Running on Render" says Yes, otherwise set `TRUSTED_PROXIES` to the connection address range or `CLIENT_IP_HEADERS` to the header that holds the IP |
| Locations always "Unknown" | ip-api.com unreachable or over the 45/minute limit; attempts still work |
| I blocked myself while practising | unblock from another network, wait, or run the SQL below |
| "The page had expired" on the sign-in page | the form came from a session the server no longer has (restart, redeploy, the free instance waking up, 30 minutes idle) or from another tab; enter the password again. Sessions live in memory, so every restart signs everyone out |

End all blocks and locks now (the rows stay as history):

```sql
UPDATE blocked_ips   SET expires_at = UTC_TIMESTAMP() WHERE expires_at > UTC_TIMESTAMP();
UPDATE account_locks SET expires_at = UTC_TIMESTAMP() WHERE expires_at > UTC_TIMESTAMP();
```

## 7. Useful database commands

```bash
mysql -u lams_user -p login_monitoring_system
```

```sql
SELECT * FROM login_attempts ORDER BY id DESC LIMIT 10;
SELECT * FROM blocked_ips WHERE expires_at > UTC_TIMESTAMP();
SELECT * FROM account_locks WHERE expires_at > UTC_TIMESTAMP();
SELECT alert_type, severity, message FROM security_alerts ORDER BY id DESC LIMIT 10;
SELECT id, name, email, role, created_at FROM users;
```

Clean history before a demo (users stay):

```sql
DELETE FROM login_attempts;
DELETE FROM blocked_ips;
DELETE FROM account_locks;
DELETE FROM security_alerts;
```

All times in the database are UTC (India is UTC + 5:30).
