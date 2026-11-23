# LAMS - Demo Workflow

This is how I demonstrate the whole project to the professor. Each step says what I do, what appears on
the screen, what I say, and where the code is if I am asked. The full demo takes about 15 minutes; a
7-minute version is at the end.

Contents

- Preparation
- Part A - Registration and login protection (user side)
- Part B - The user's security page
- Part C - The admin dashboard
- Part D - Admin actions
- Part E - Attack simulator
- Part F - Full account-takeover story
- Part G - Showing the code, database and tests
- 7-minute version
- If something goes wrong

---

## Preparation

**Devices.** Rules are per IP address, so I need two different IPs:

| Role | Device | Why |
|---|---|---|
| Admin | laptop on Wi-Fi | stays signed in as admin the whole time |
| "Attacker" / second device | phone on **mobile data** (Wi-Fi off) | has a different public IP, so blocking it does not block my laptop |

Running locally on one laptop also works: `http://localhost:8090` and `http://127.0.0.1:8090` count as
two different IPs (IPv6 `::1` and IPv4 `127.0.0.1`).

**Before the session**

1. Open the live site 2-3 minutes early. The free Render server sleeps after 15 minutes and needs about a
   minute to wake up.
2. Log in as admin -> Overview -> scroll down to **Connection Check**. "Your IP as seen by LAMS" must be
   my real public IP and "Found using" must say `Header CF-Connecting-IP`.
3. Register a demo user, for example `demo.student@example.com` / `Campus2026demo`, and log in once on
   the laptop, then log out. This makes the laptop's IP a "known" IP for that account (needed for Rule 4).
4. Admin -> Attack Simulator -> **Clear simulated data**, so the dashboard starts clean.
5. Keep two windows ready on the laptop: a normal window for the admin and a private window for the demo
   user.

---

## Part A - Registration and login protection

### A1. Registration and password rules

| | |
|---|---|
| Do | Open Register. Submit with a bad email, a 5-character password and a different confirmation. |
| See | An error under each field ("valid email", "8 to 64 characters", "passwords do not match"). |
| Do | Try the password `Password123`. |
| See | "This password has appeared in N known data breaches. Please choose a different one." |
| Say | "Passwords are checked against Have I Been Pwned. Only the first 5 characters of the SHA-1 hash leave the server, the rest is compared locally (k-anonymity). The password is stored as a BCrypt hash, and every new account gets the USER role." |
| Code | `AuthController.register`, `BreachedPasswordService.breachCount`, `RegistrationRequest` |

If `Password123` is accepted, the breach service could not be reached. I explain that the check is
fail-open on purpose, so an outage never stops people from registering.

### A2. Normal login

| | |
|---|---|
| Do | Log in as the demo user on the laptop. |
| See | The My Security page: green banner, last login, active session, the login in the activity list. |
| Say | "Every login, successful or not, is saved with IP, location, browser and device." |

Log out again (top right).

### A3. Wrong passwords and the counter (Rule 1)

On the **phone**:

| | |
|---|---|
| Do | Enter the demo user's email with a wrong password. |
| See | "Invalid email or password." and "Attempt 1 of 5 - 4 left" with five dots. |
| Do | Pull down to **refresh** the page. |
| See | The counter is still "1 of 5". |
| Say | "The counter is not in the browser. The page reads it from the database for this email and this IP, so a refresh cannot reset it." |
| Do | Wrong password 4 more times. |
| See | "Sign-in to ... is paused on this network. Try again in 14:59" with a live countdown. |
| Do | Enter the **correct** password. |
| See | Still paused. |
| Say | "The lock is checked before the password, in my filter that runs before Spring Security's login filter. Even the right password is refused." |
| Do | On the laptop, log in as the demo user with the correct password. |
| See | It works. |
| Say | "Rule 1 locks the account only for the network the guesses came from. Other students on the same Wi-Fi, and the real user at home, are not affected." |
| Code | `LoginProtectionService.applyRules` (Rule 1), `checkBeforeLogin`, `statusFor`, `templates/login.html` |

### A4. One IP trying many accounts (Rules 2 and 3)

On the phone, click **Use a different email** and try wrong passwords for different emails, for example
`a@example.com`, `b@example.com`, `c@example.com`.

| | |
|---|---|
| See | After the third one: "Warning for your network: N failed sign-ins in the last 10 minutes (3 different accounts). The network is blocked at 10 failures or 4 accounts." |
| Do | One more email, `d@example.com`. |
| See | "Your IP address has been temporarily blocked." with a countdown, and the Sign in button is disabled. |
| Say | "This is credential stuffing: one IP trying leaked passwords on many accounts. Rule 2 blocks the whole IP after 4 different accounts. Rule 3 blocks after 10 failures in total. A blocked IP is refused for every account." |
| Code | `applyRules` (Rules 2 + 3), `BlockedIpService.blockAutomatically` |

### A5. Wrong form input is not counted

| | |
|---|---|
| Do | (laptop, private window) Submit the login form with an empty password using the browser's developer tools, or just mention it. |
| Say | "An incomplete form is not a password guess, so it is not counted (`LoginFailureHandler`)." |

---

## Part B - The user's security page

Log in as the demo user on the laptop (private window). Keep the phone logged in as the same user too
(from home Wi-Fi earlier or from a different network after the block ends), or use a second browser.

### B1. Warning banner and activity

| | |
|---|---|
| See | Orange banner: "5 failed sign-in attempt(s) on your account since your last login." |
| See | Recent Login Activity: each attempt with result, IP, location (flag + city), device (e.g. "Chrome on Android, Mobile"), and warning signs. |
| Say | "The user can see exactly who tried to get into their account. Location comes from the IP via ip-api.com and is cached in the `ip_info` table." |
| Code | `AccountController.dashboard`, `IpIntelService`, `UserAgentParser` |

### B2. Active sessions and sign out other devices

| | |
|---|---|
| See | Active Sessions lists each device with IP, location and sign-in time; "THIS DEVICE" marks the current one. |
| Do | Click **Sign out all other devices**. Then refresh the other device. |
| See | The other device lands on the login page with "Your session was ended from another device." |
| Say | "Spring Security's SessionRegistry knows every session. I call expireNow() on the others, and the ConcurrentSessionFilter logs them out on their next request. The page never shows real session ids, only random handles." |
| Code | `SessionTracker.expireOthers`, `SecurityConfig` (sessionConcurrency) |

### B3. Change password

| | |
|---|---|
| Do | Menu -> Change Password. Wrong current password first. |
| See | "Your current password is not correct." |
| Do | Correct current password and a new one. |
| See | Back on My Security with "Your password was changed." |
| Say | "New passwords also go through the breach check, and changing the password signs out the other devices." |

"This wasn't me" is shown in Part F.

---

## Part C - The admin dashboard

Laptop, admin window -> **Overview** (refresh).

### C1. Summary cards and chart

| | |
|---|---|
| See | Cards: total, failed, successful, requests stopped, blocked IPs now (+ locked accounts), open alerts. |
| See | Login Activity chart, stacked green/red/orange per hour. Click **7 days** to switch. |
| Say | "Everything here is read from MySQL on each request. The chart is SVG drawn by the server (StatsService), no JavaScript library." |

### C2. Top lists

| | |
|---|---|
| See | Top Attacking IPs (with location and VPN / DATA CENTRE tags), Most Targeted Accounts, Attempts by Country. |
| Say | "This tells the admin where attacks come from and who is being targeted." |

### C3. Alerts and blocked IPs

| | |
|---|---|
| See | Open Alerts: "Brute force on one account" (MEDIUM) from A3 and "Credential stuffing" (HIGH) from A4. Blocked Right Now: the phone's IP with remaining time. |
| Do | Click **Done** on one alert. |

### C4. Live feed

| | |
|---|---|
| Do | Leave the overview open. On the phone, try one more login. |
| See | Within 5 seconds the new row appears at the top of the Live Feed (highlighted). |
| Say | "The page asks `/admin/api/feed?after=<last id>` every 5 seconds. New rows are built with textContent, so an email typed by an attacker cannot inject HTML." |

### C5. Rules and connection check

| | |
|---|---|
| See | Active Protection Rules lists all 5 rules with the current numbers. Connection Check shows my IP, "Found using: Header CF-Connecting-IP", and the proxy headers. |
| Say | "On Render the app sits behind Cloudflare. Cloudflare puts the visitor's real IP in CF-Connecting-IP and overwrites fake values, so I trust that header. This panel proves the IP detection works." |
| Code | `ClientIpResolver.resolveDetailed` |

### C6. Attempt log and CSV

| | |
|---|---|
| Do | Attempt Log. Set Status = FAILED (applies at once). Type part of the demo email in Email -> Search. |
| See | Only the matching rows, with reason ("Wrong password", "No such account"), device and risk. Pages of 50. |
| Do | **Download CSV**, open it. |
| Say | "Cells that start with = + - @ get a quote in front, so Excel does not run them as formulas." |

### C7. IP details

| | |
|---|---|
| Do | Click the phone's IP anywhere. |
| See | Location, ISP, network type, total/failed/stopped counts, first/last seen, accounts tried from this IP, block history, alerts about this IP, latest attempts. |
| Say | "This is the investigation page for one attacker." |

---

## Part D - Admin actions

All of these are POST forms with a CSRF token, and each one is written to the Audit Log.

### D1. Lift a lock and unblock an IP

| | |
|---|---|
| Do | Blocks & Locks -> Account Locks -> **Lift** the demo user's lock. Blocked IPs -> **Unblock** the phone's IP. |
| Do | On the phone, log in with the correct password. |
| See | It works again. |

### D2. Manual block and permanent ban

| | |
|---|---|
| Do | Blocks & Locks -> Block an IP: enter the phone's IP, choose **Permanently (ban)**, reason "demo". |
| Do | On the phone, open the login page. |
| See | "Access from your IP address has been blocked by the administrator." |
| Do | Try to block the laptop's own IP. |
| See | "You cannot block your own IP address." |
| Do | Unblock the phone again. |

### D3. Trusted IPs (allow-list)

| | |
|---|---|
| Do | Add the phone's IP (or a range like `10.10.0.0/16`) with note "College lab". |
| Say | "Trusted networks are never blocked by the IP rules, but account protection still applies." |
| Do | Remove it again. |

### D4. Users

| | |
|---|---|
| Do | Users -> **Disable** the demo user while they are logged in on the phone. Refresh the phone. |
| See | The phone is logged out; logging in shows "Your account is disabled". |
| Do | **Enable** again. Also show **Unlock** and **Sign out**. |
| Say | "Admins cannot disable their own account." |

### D5. Audit log

| | |
|---|---|
| See | Every action from D1-D4 with admin email, action (BLOCK_IP, UNBLOCK_IP, LIFT_LOCK, DISABLE_USER, ...), target and time. |

---

## Part E - Attack simulator

Admin -> Attack Simulator. I explain first: "These are made-up attacks, but they go through the same
methods as real logins, so the real rules react. The IPs come from reserved documentation ranges that no
real computer has, and everything is marked SIMULATED."

Run them in this order (Distributed last, because it locks the account for new IPs):

| Scenario | Target | Result to point at | Then show |
|---|---|---|---|
| Credential stuffing | nobody@example.com | step list: 4 failures, then "IP BLOCKED", the rest "REJECTED before password check" | Overview: Blocked Right Now, HIGH alert, Python User-Agent in the feed |
| Brute force | a second test user | 5 failures, "RULE 1: account locked for this IP", 2 rejected | Blocks & Locks: lock "Only for IP 203.0.113.66" |
| Account takeover | the demo user | 3 failures, then "SUCCESSFUL LOGIN ... risk flags: After failed attempts, VPN / data centre IP, New device" | Alerts: CRITICAL "Suspicious successful login" |
| Distributed attack | the demo user | 5 countries take turns; after 8 failures "RULE 4: account locked for new IPs" | the laptop (known IP) can still log in as the demo user |

Then the 7-day chart and the country list fill up with the attack traffic. At the end:
**Clear simulated data** removes only simulated rows; real data stays.

Code: `SimulatorService.run`, `SimulatorService.attempt`.

---

## Part F - Full account-takeover story

This is the strongest part of the demo because it connects everything.

1. Admin runs **Account takeover** against the demo user (if not done in Part E).
2. Demo user logs in on the laptop (private window).
3. See: the orange banner, and at the top of the activity list a SUCCESS from Singapore with the tags
   "After failed attempts", "VPN / data centre IP", "New device".
4. Say: "The attacker logged in with the right password. LAMS cannot know it was not the owner, but it
   flags the login because a success right after failures from a VPN in a new place is suspicious."
5. Click **This wasn't me** -> confirm.
6. See: the Change Password page with "We signed out N other session(s). IP 192.0.2.150 has been blocked
   for 24 hours. Please choose a new password now."
7. Change the password.
8. Admin -> Alerts: a new HIGH alert "Login reported by account owner". Blocks & Locks: the attacker's IP
   with source USER_REPORT.
9. Say: "So the user and the admin work together: the system detects, the user confirms, and the attacker
   is locked out."

---

## Part G - Showing the code, database and tests

If the professor wants to see inside:

**Code to open (in this order)**

1. `config/SecurityConfig.java` - the filter is added before `UsernamePasswordAuthenticationFilter`.
2. `security/LoginProtectionFilter.java` - refuses blocked requests before the password check.
3. `service/LoginProtectionService.java` - `checkBeforeLogin`, `applyRules` (Rules 1-4), `recordSuccess`
   (risk flags), `statusFor` (login page counter).
4. `service/BlockedIpService.java` - `blockAutomatically` (Rule 5 escalation).
5. `security/ClientIpResolver.java` - real visitor IP.

**Database (MySQL Workbench or the terminal)**

```sql
SELECT id, ip_address, attempted_email, outcome, reason, attempted_at
FROM login_attempts ORDER BY id DESC LIMIT 10;

SELECT ip_address, blocked_at, expires_at, reason, source, block_level
FROM blocked_ips ORDER BY id DESC;

SELECT email, ip_address, lock_type, expires_at FROM account_locks ORDER BY id DESC;

SELECT alert_type, severity, message FROM security_alerts ORDER BY id DESC LIMIT 5;

SELECT name, email, role, LEFT(password_hash, 7) AS hash_start FROM users;
```

Point out: times are in UTC, `expires_at` = `blocked_at` + 15 minutes, passwords are BCrypt hashes
starting with `$2a$`.

**Tests**

```bash
./mvnw test
```

Ends with `Tests run: 106, Failures: 0, Errors: 0`. I mention that the tests use a test clock to jump
15 minutes forward and set fake client IPs, so the time-based rules are tested without waiting.

---

## 7-minute version

1. A3 - wrong passwords on the phone, counter survives refresh, lock with countdown, laptop still works.
2. A4 - four different emails, network warning, IP blocked with disabled button.
3. C1-C4 - overview: cards, chart, top lists, alerts, live feed.
4. E - credential stuffing and account takeover in the simulator.
5. F - demo user sees the flagged login, presses This wasn't me.
6. G - `./mvnw test` result and one look at `LoginProtectionService`.

---

## If something goes wrong

| Problem | Fix |
|---|---|
| My laptop's IP got blocked | Unblock it from the phone, or wait 15 minutes, or in MySQL: `UPDATE blocked_ips SET expires_at = UTC_TIMESTAMP() WHERE expires_at > UTC_TIMESTAMP();` |
| A simulator scenario says "REJECTED before password check" for every step | an earlier scenario already locked that account - Clear simulated data and run again |
| Location shows "Unknown" | the free lookup was slow - IP page -> Look up location again |
| Site is very slow at first | it was asleep - wait a minute and refresh |
| "The page had expired, so your password was not checked" | the login page was older than the session (server restarted or woke up, page open for 30+ minutes, or I signed in/out in another tab) - type the password again |
| Every visitor shows the same IP | the proxy setup is wrong - check Connection Check, see SETUP_AND_DEPLOYMENT.md |
| `Password123` is accepted | the breach service was unreachable; explain the fail-open design |
