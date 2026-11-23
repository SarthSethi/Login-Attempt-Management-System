# LAMS - Project Guide

These are my notes on how the Login Attempt Monitoring System works, why I built it this way, and where
everything is in the code. I wrote them so I can explain any part of the project in the viva.

Contents

1. What the project does
2. Technologies I used
3. How the code is organised
4. What happens when someone logs in
5. Finding the real IP address
6. The five detection rules
7. Checking successful logins
8. The login page counter
9. Database tables
10. Features for normal users
11. Features for the administrator
12. Outside services
13. Security measures
14. Configuration
15. Testing
16. Limitations and next steps
17. Numbers to remember

---

## 1. What the project does

LAMS is a login and registration website that protects itself against password attacks. Every login
attempt is saved in MySQL with the IP address, the email that was typed, the result, the reason, the
browser/device and the time. On top of that it runs five detection rules that decide whether an
account or an IP address should be stopped for a while.

I designed it around the four password attacks that real websites see:

- **Brute force** - one attacker guesses many passwords for one account.
- **Credential stuffing** - one attacker takes a leaked list of email/password pairs from another site
  and tries them here, one or two tries per account.
- **Distributed attack** - many computers (a botnet) each try a few passwords for the same account, so
  no single IP looks bad.
- **Account takeover** - the attacker finally guesses the right password, so the login succeeds.

My first version only had one rule: "5 failures from one IP in 10 minutes block that IP for 15
minutes". While testing it I saw three problems with that:

1. On Render the app saw the address of Render's internal proxy instead of the visitor, so the stored
   IPs were wrong.
2. Everyone on the same college Wi-Fi shares one public IP, so one person's typos would block everyone.
3. An attacker who changes IP, or who uses a botnet, was never stopped.

So the final version looks at the attempts from three directions: the account and the IP together,
the IP across all accounts, and the account across all IPs. It also checks successful logins, because
a correct password does not prove that the owner typed it.

## 2. Technologies I used

| What | Technology | Why I picked it |
|---|---|---|
| Language | Java 21 | LTS version, records and switch expressions keep the code short |
| Framework | Spring Boot 4.1 | Starts a web server with almost no setup, dependency injection |
| Security | Spring Security 7 | Form login, BCrypt, CSRF, sessions and roles are already built in and tested |
| Pages | Thymeleaf + HTML/CSS + a small JS file | Server-side pages, output is escaped automatically |
| Database | MySQL 8 | Required by the project; Aiven gives a free MySQL in the cloud |
| ORM | Spring Data JPA / Hibernate 7 | Repositories write the SQL for me, always with bound parameters |
| Tests | JUnit 5, MockMvc, Mockito, H2 | Tests run without a MySQL server or internet |
| Hosting | Docker on Render + MySQL on Aiven | Both have free plans |

Charts on the admin page are plain SVG drawn by the server (StatsService), so I did not need a chart
library and the Content-Security-Policy can stay strict.

## 3. How the code is organised

```text
src/main/java/com/example/loginmonitoring/
  config/       SecurityConfig, property records (LoginSecurityProperties, ClientIpProperties,
                IntegrationProperties, AdminProperties), AppConfig (Clock, SessionRegistry),
                AdminInitializer (creates the admin at startup), DateDisplay
  controller/   AuthController (/login, /register), AccountController (/dashboard, /account/**),
                AdminController (admin pages), AdminActionController (admin POST actions),
                AdminModelAdvice (open alert count for the menu badge)
  entity/       User, LoginAttempt, BlockedIp, AccountLock, SecurityAlert, IpInfo,
                IpAllowlistEntry, AdminAction + enums
  repository/   one Spring Data JPA interface per table
  security/     ClientIpResolver, LoginProtectionFilter, LoginFailureHandler,
                LoginSuccessHandler, LoginRedirects, LoginFormFields
  service/      LoginProtectionService (the rules), LoginAttemptService, BlockedIpService,
                AccountLockService, AlertService, AllowlistService, AdminAuditService,
                SessionTracker, StatsService, SimulatorService, RetentionJob, UserService,
                CustomUserDetailsService, LoginStatus
  service/intel/ IpIntelService, IpClassifier, UserAgentParser, BreachedPasswordService
  dto/          form objects and small result records
src/main/resources/templates/   login, register, dashboard, password, fragments, error/, admin/
src/test/java/...               106 automated tests
```

It is a normal layered Spring application: controllers handle pages, services hold the logic,
repositories talk to the database. The security layer runs before the controllers.

## 4. What happens when someone logs in

The login form posts to `/login`. Spring Security handles that URL itself, so there is no controller
method for it. The request goes through a chain of filters:

```text
POST /login
  -> CsrfFilter                       token missing or old -> refused, nothing checked or saved
  -> LoginProtectionFilter (mine)     IP blocked or account locked? -> save BLOCKED, redirect, stop
  -> UsernamePasswordAuthenticationFilter
       CustomUserDetailsService loads the user by email
       BCrypt compares the password with password_hash
  -> LoginSuccessHandler / LoginFailureHandler (mine)
```

**Old forms (`CsrfFailureHandler`).** The CSRF token belongs to one session. If the session is gone
(server restart or redeploy, the free Render instance waking up, 30 minutes idle) or was replaced
because I signed in or out in another tab, the form's token no longer matches. Spring's default answer
is a bare 403 page, which looked like "access denied" even with the right password. My handler still
refuses the request but explains it: the sign-in form goes back to `/login?retry` with the email
filled in ("The page had expired, so your password was not checked"), the register form goes back to
`/register?retry`, any other form after the session ended goes to `/login?timeout`, and a signed-in
user with an old token gets a 403 page that says the form expired. A user without the ADMIN role who
opens `/admin` still gets the normal 403.

The most important design decision is where my filter sits. In `SecurityConfig`:

```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/login", "/register", "/error", "/css/**", "/js/**", ...).permitAll()
        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated())

    // Block / lock check happens before the email/password check
    .addFilterBefore(protectionFilter, UsernamePasswordAuthenticationFilter.class)

    .formLogin(form -> form
        .loginPage("/login")
        .usernameParameter("email")
        .successHandler(successHandler)
        .failureHandler(failureHandler))
    ...
    .sessionManagement(session -> session
        .sessionFixation(fixation -> fixation.changeSessionId())
        .sessionConcurrency(c -> c.maximumSessions(-1).sessionRegistry(sessionRegistry)
                                  .expiredUrl("/login?expired")))
```

Because `LoginProtectionFilter` runs before `UsernamePasswordAuthenticationFilter`, a blocked
attacker never reaches the password check. Even the correct password is refused, so guessing becomes
useless while the block lasts.

The filter itself only handles `POST /login`:

```java
AttemptContext context = AttemptContext.real(clientIpResolver.resolve(request),
        request.getParameter("email"), request.getHeader("User-Agent"));

Optional<Denial> denial = protectionService.checkBeforeLogin(context.ip(), context.email());
if (denial.isPresent()) {
    protectionService.recordDenied(context, denial.get());      // saved as BLOCKED
    LoginRedirects.rememberEmail(request, context.email());
    response.sendRedirect(request.getContextPath() + LoginRedirects.forDenial(denial.get()));
    return;                                                      // chain stops here
}
chain.doFilter(request, response);
```

I create this filter in `SecurityConfig` with `new` and did not mark it `@Component`. If it were a
component, Spring Boot would also register it as a normal servlet filter that runs before the CSRF
check, which I do not want.

After the password check, `LoginFailureHandler` works out the reason (wrong password, unknown email
or disabled account), passes it to `LoginProtectionService.onFailure(...)`, and redirects to
`/login?error`, `/login?locked`, `/login?blocked` or `/login?disabled`. The visitor always sees
"Invalid email or password" for both unknown email and wrong password, so nobody can find out which
emails are registered. The real reason is only stored for the admin.

`LoginSuccessHandler` calls `onSuccess(...)` (risk check), registers the session's device for the
"active sessions" list, and sends users to `/dashboard` and admins to `/admin`.

## 5. Finding the real IP address

Every rule depends on the IP, so it has to be right and it must not be possible to fake it.
`ClientIpResolver` decides it in this order:

```java
// 1. A visitor-IP header set by a proxy we trust (on Render: CF-Connecting-IP)
if (render || fromTrustedProxy) {
    for (String headerName : clientIpHeaders) {
        String candidate = normalize(firstValue(request.getHeader(headerName)));
        if (candidate != null) {
            return new Resolution(candidate, "Header " + headerName, remoteAddress, seen);
        }
    }
}
// 2. X-Forwarded-For, but only when the sender is one of our proxies (read right to left)
if (fromTrustedProxy) { ... walkForwardedFor(forwardedFor, remoteAddress) ... }
// 3. Otherwise the TCP connection address, which a client cannot fake
return new Resolution(remoteAddress, "Direct connection", remoteAddress, seen);
```

On Render every request goes Browser -> Cloudflare -> Render's proxy -> my app, so `getRemoteAddr()`
is Render's proxy (10.x.x.x), not the visitor. Cloudflare writes the visitor's real IP into the
`CF-Connecting-IP` header and overwrites it if a visitor sends their own, so that header can be
trusted. Render sets the environment variable `RENDER=true` on every service, and I use that to switch
this mode on automatically.

`X-Forwarded-For` is different: a visitor can pre-fill it with anything, and proxies only append to
it. So I only read it when the request came from a trusted proxy, and I read it from the right,
skipping my own proxies. Entries further left were written by the client and are ignored.

`normalize()` only accepts IP literals (it checks the pattern before calling `InetAddress`), so a
header like `evil.example.com` never causes a DNS lookup. IPv6 addresses are normalised so the same
client always gets the same text.

The admin overview has a "Connection Check" panel that shows which IP was detected and how, which is
how I verify the setup after deploying.

## 6. The five detection rules

All rules live in `LoginProtectionService`. There are three entry points:

- `checkBeforeLogin(ip, email)` - before the password is checked
- `onFailure(context, reason)` - after a wrong password
- `onSuccess(context)` - after a correct password

### Before the password check

```java
Optional<BlockedIp> block = blockedIpService.findActiveBlock(ip);
if (block.isPresent()) -> Denial(IP_BLOCKED, ...)

for (AccountLock lock : accountLockService.activeLocks(email)) {
    if (lock.getType() == LockType.ACCOUNT_IP && ip.equals(lock.getIpAddress()))
        -> Denial(ACCOUNT_IP_LOCKED, ...)          // Rule 1 lock for this IP
    if (lock.getType() == LockType.ACCOUNT && !isKnownIp(email, ip, now) && !allowlisted(ip))
        -> Denial(ACCOUNT_LOCKED, ...)             // Rule 4 lock, only for new IPs
}
```

A block or lock is "active" when `expires_at > now`. There is no background job that removes them;
after the time passes the condition is simply false and the old row stays as history.

### After a wrong password

`onFailure` saves the FAILED attempt and then applies the rules. It runs inside one lock
(`ReentrantLock`) and one database transaction, so two requests at the same moment can never both
miss a limit or create two blocks. This is correct because the app runs as a single instance.

**Rule 1 - one account from one IP (brute force).** 5 failures in 10 minutes lock only that pair for
15 minutes.

```java
long pairFailures = countPairFailures(email, ip, now, lastPairLock);
if (pairFailures >= properties.maxFailedAttempts()) {
    AccountLock lock = accountLockService.lockPair(email, ip, ...);
    alertService.raise(AlertType.BRUTE_FORCE, AlertSeverity.MEDIUM, ip, email, ...);
}
```

`countPairFailures` counts from the latest of three moments: 10 minutes ago, the last lock for this
pair, and the last successful login of this pair. So failures that already caused a lock are not
counted again, and a successful login resets the counter.

Why the pair and not the whole IP? Because of shared networks. If one student mistypes 5 times, only
their own account is paused on that network. Other students on the same Wi-Fi are not affected, and
the same student can still log in from home.

**Rules 2 and 3 - one IP across all accounts.** These block the whole IP:

```java
LocalDateTime from = ipCountFrom(ip, now);       // 10 min ago, or the IP's last block
long accounts = attemptRepository.countDistinctEmailsFromIp(ip, FAILED, from);
long failures = attemptRepository.countByIpAddressAndOutcomeAndAttemptedAtAfter(ip, FAILED, from);
if (accounts >= properties.ipMaxAccounts())      // Rule 2: 4 different accounts
    why = "Credential stuffing: ...";
else if (failures >= properties.ipMaxFailures()) // Rule 3: 10 failures
    why = "Too many failed attempts: ...";
if (why != null) blockedIpService.blockAutomatically(ip, why, ...);
```

Rule 2 catches credential stuffing: a script that tries leaked pairs uses each account only once or
twice, so Rule 1 never fires, but it touches many different accounts. Rule 3 is the classic volume
rule with a higher threshold than the old version.

**Rule 4 - one account from many IPs (distributed attack).**

```java
long failures = attemptRepository.countByAttemptedEmailAndOutcomeAndAttemptedAtAfter(email, FAILED, from);
long ips = attemptRepository.countDistinctIpsForEmail(email, FAILED, from);
if (failures >= properties.accountMaxFailures() && ips >= properties.accountMinIps()) {
    accountLockService.lockAccount(email, ...);
    alertService.raise(AlertType.DISTRIBUTED_ATTACK, AlertSeverity.HIGH, null, email, ...);
}
```

8 failures from at least 3 different IPs mean a botnet. I deliberately do not lock the account
completely, because then anybody could lock any user out on purpose just by typing wrong passwords.
Instead, only IPs that the owner has never logged in from (in the last 90 days) are refused. The real
owner keeps working from home or college, the botnet is stopped.

**Rule 5 - repeat offenders.** In `BlockedIpService.blockAutomatically`:

```java
int level = (int) blockedIpRepository.countBlocksSince(ip, blockedAt.minus(properties.repeatWindow()),
        BlockSource.AUTOMATIC) + 1;
Duration duration = properties.blockDurationForLevel(level);   // 15 min, 1 h, 24 h
```

The first automatic block is 15 minutes, a second one within 24 hours is 1 hour, the third and later
are 24 hours. The alert for a repeat block has severity CRITICAL.

**Trusted IPs.** IPs or CIDR ranges on the allow-list (for example the college network) are never
blocked by Rules 2, 3 and 5. Rule 1 and Rule 4 still apply, because they protect accounts.

Locks work for any typed email, even one without an account. That way a lock message never reveals
whether an account exists.

## 7. Checking successful logins

`onSuccess` first looks up the IP's location (`IpIntelService.lookupNow`), then compares this login
with the user's earlier successful logins:

| Flag | Points | When |
|---|---|---|
| AFTER_FAILURES | 3 | 3 or more failures on this account since its last success (max. 1 hour) |
| NEW_COUNTRY | 2 | the country was never seen in this user's earlier logins |
| VPN_OR_HOSTING | 2 | the IP belongs to a VPN/proxy or a data centre |
| AUTOMATED_CLIENT | 2 | the User-Agent is curl, a Python script, Hydra, ... |
| NEW_DEVICE | 1 | this browser + OS combination was never used before |

The flags and the score are saved on the attempt. If the score is 2 or more an alert is raised:
MEDIUM for 2, HIGH for 3-4, CRITICAL for 5 or more. "After failed attempts" is worth the most because
a success right after several failures is the typical sign of a guessed password.

The user sees the same flags on their own page and can press "This wasn't me".

## 8. The login page counter

The login page shows "Attempt 2 of 5 - 3 left" with five dots, a countdown when the account is paused
or the IP is blocked, and a warning when the whole network is close to being blocked.

The counter does not live in the browser. When the login fails I store the typed email in the
visitor's session (`LoginRedirects.rememberEmail`). Every time `/login` is opened, `AuthController`
calls:

```java
LoginStatus status = protectionService.statusFor(clientIpResolver.resolve(request),
        LoginAttemptService.cleanEmail(lastEmail));
```

`statusFor` counts the failures in MySQL with the same `countPairFailures` and `ipCountFrom` methods
that the rules use. So the page always shows the real number, and refreshing the page cannot reset
it. The countdown is calculated by the server (seconds until `expires_at`), and `dashboard.js` only
counts it down. While the IP is blocked the Sign in button is disabled.

If the counter ever seems to reset on the live site, it means the IP is changing between requests
(the proxy setup is wrong). The Connection Check panel shows that.

## 9. Database tables

Hibernate creates and updates the tables on startup (`spring.jpa.hibernate.ddl-auto=update`). All
times are stored in UTC and only converted to Indian time on the page (`DateDisplay`). The full SQL is
in [schema.sql](schema.sql), and the ER diagram is `diagrams/03-er-diagram.png`.

| Table | One row per | Important columns |
|---|---|---|
| users | account | email (unique, lower case), password_hash (BCrypt), role USER/ADMIN, enabled |
| login_attempts | submitted login form | ip_address, attempted_email, outcome (SUCCESS/FAILED/BLOCKED), reason, attempted_at, browser, os, device_type, risk_flags, risk_score, simulated, reported |
| blocked_ips | IP block | ip_address, blocked_at, expires_at, reason, source (AUTOMATIC/MANUAL/USER_REPORT), block_level, created_by, lifted_by |
| account_locks | account lock | email, ip_address (null = all new IPs), lock_type (ACCOUNT_IP/ACCOUNT), locked_at, expires_at |
| security_alerts | alert for the admin | alert_type, severity, ip_address, email, message, acknowledged |
| ip_info | IP address (cache) | country, country_code, city, isp, asn, is_proxy, is_hosting, status |
| ip_allowlist | trusted IP/range | cidr, note, created_by |
| admin_actions | admin change (audit log) | admin_email, action, target, detail, created_at |

Things I can explain about the design:

- There are no foreign keys between attempts, users and IPs on purpose. Attempts are saved even for
  emails that have no account (attackers guess emails) and for IPs that were never blocked.
- The indexes match the queries: `(ip_address, attempted_at)` for "failures of this IP in the last
  10 minutes", `(attempted_email, attempted_at)` for the account rules, `(ip_address, expires_at)` for
  "is this IP blocked now".
- The columns I added in version 2 are nullable, so Hibernate could add them to the existing Aiven
  database without touching old rows. I tested this upgrade on MySQL 8 with
  `sql_require_primary_key=ON`, which is how Aiven is configured.
- Passwords, cookies and session ids are never stored.
- `RetentionJob` deletes attempts older than 180 days every night at 03:30 UTC, which keeps the
  free database small. 180 days matches CERT-In's direction on log retention.

## 10. Features for normal users

**Registration.** Name, email, password twice. Email must be unique, the password 8-64 characters with
at least one letter and one digit. Every new account gets the USER role; there is no role field, so
nobody can register as admin. The password is also checked against known data breaches (section 12).

**My Security page (`/dashboard`).** `AccountController.dashboard` builds:

- a banner: green (no failed attempts since the last login), orange (N failed attempts), or red (the
  account is under a Rule 4 lock right now)
- account details and the last login with location and device
- active sessions, from Spring Security's `SessionRegistry` plus the device info I store in
  `SessionTracker`
- the last 25 attempts on this account with result, IP, location, device and warning signs

**Sign out other devices.** `SessionTracker.expireOthers` calls `expireNow()` on the user's other
sessions. On their next request Spring Security's `ConcurrentSessionFilter` logs them out and sends
them to `/login?expired`. Pages never show real session ids, because whoever has a session id is
logged in; each session gets a random "handle" instead.

**This wasn't me.** Available on any successful login that is not the current session. It:

1. marks the attempt as reported
2. signs out every other session of the user
3. blocks the IP of that login for 24 hours (unless it is the user's current IP or a trusted IP)
4. raises a USER_REPORTED alert for the admin
5. opens the Change Password page

**Change password.** Current password, new password twice, breach check, and it signs out the other
devices.

## 11. Features for the administrator

The admin account is created at startup from `ADMIN_EMAIL` and `ADMIN_PASSWORD`
(`AdminInitializer`). Everything under `/admin/**` needs the ADMIN role.

| Page | What it does | Main code |
|---|---|---|
| Overview | summary cards, activity chart (24 h or 7 days), top attacking IPs, most targeted accounts, attempts by country, open alerts, blocked IPs, live feed, active rules, connection check | `AdminController.overview`, `StatsService` |
| Attempt Log | all attempts, filter by status / IP / email, 50 per page, CSV download | `AdminController.attempts`, `attemptsCsv` |
| IP details | location, ISP, VPN flags, accounts tried, block history, alerts, buttons to block, unblock or trust | `AdminController.ipDetail` |
| Blocks & Locks | manual block (1 h, 24 h, 7 days, permanent), active blocks, account locks with Lift, trusted list, history | `AdminController.protection`, `AdminActionController` |
| Alerts | alerts with severity, mark one or all as handled | `AlertService` |
| Users | enable/disable (disabling also signs the user out), unlock, sign out | `AdminActionController` |
| Attack Simulator | four demo attacks through the real rules | `SimulatorService` |
| Audit Log | every admin change | `AdminAuditService` |

A few details worth knowing:

- The live feed calls `GET /admin/api/feed?after=<last id>` every 5 seconds and adds new rows with
  `textContent`, never `innerHTML`, so attacker-typed emails cannot run as HTML.
- The chart is SVG: `StatsService.activityChart` puts attempts into 24 hourly (or 7 daily) buckets in
  Indian time and calculates the rectangle heights. The template only draws them.
- In the CSV export, cells that start with `=`, `+`, `-` or `@` get a `'` in front, so Excel does not
  run them as formulas (CSV injection).
- An admin cannot block their own IP, cannot block a trusted IP, and cannot disable their own account.
- Every admin POST has the CSRF token and is written to the audit log.

**Attack simulator.** `SimulatorService.run` sends made-up attempts through exactly the same methods
as real logins (`checkBeforeLogin`, `onFailure`, `onSuccess`), so the rules really react. It uses the
reserved documentation IP ranges 192.0.2.x, 198.51.100.x and 203.0.113.x, which no real computer has,
with invented countries. Every row it creates is marked `simulated`, and "Clear simulated data"
deletes all of them.

| Scenario | What it sends | Rule that fires |
|---|---|---|
| Brute force | one IP, 7 wrong passwords for one account, User-Agent "Hydra" | Rule 1 after 5 |
| Credential stuffing | one IP, 10 different emails, Python User-Agent | Rule 2 after 4 accounts |
| Distributed attack | 5 IPs, 2 tries each on one account | Rule 4 after 8 failures from 3+ IPs |
| Account takeover | VPN IP, 3 failures then the correct password | success flagged, CRITICAL alert |

## 12. Outside services

Both are free, need no account, and the app keeps working when they are not reachable.

**IP location - ip-api.com.** `IpIntelService` asks for country, city, ISP, AS number and the
proxy/hosting/mobile flags. Each IP is looked up once and cached in `ip_info` (30 days; failed lookups
are retried after 1 hour). Private addresses (192.168.x, 10.x, 127.0.0.1) and the documentation
ranges are recognised locally by `IpClassifier`, without a network call. Failed logins are looked up
by a background job every 15 seconds, so the login page is never slowed down. Successful logins are
looked up straight away (with a 2.5 second limit), because the "new country" flag needs it. I also
keep under the free limit of 45 lookups per minute with a simple counter.

**Breached passwords - Have I Been Pwned "Pwned Passwords".** `BreachedPasswordService`:

```java
String hash = sha1Hex(password);              // e.g. 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
String prefix = hash.substring(0, 5);         // only "5BAA6" is sent
String body = restClient.get().uri(".../range/" + prefix).retrieve().body(String.class);
return OptionalLong.of(findCount(body, hash.substring(5)));   // compared here, locally
```

The service returns every leaked hash that starts with those 5 characters (hundreds of them), and I
compare the rest of the hash locally. So the password, and even its full hash, never leave my server.
This is called k-anonymity. If the service is down the check returns "unknown" and registration is
allowed (fail-open), so an outage never stops people from registering. NIST SP 800-63B recommends
refusing passwords that appear in breach lists.

## 13. Security measures

| Threat | What I did |
|---|---|
| Password guessing | Rules 1-5, checked before authentication |
| Stolen database | only BCrypt hashes are stored (salted, deliberately slow) |
| SQL injection | only Spring Data derived queries and JPQL with named parameters; tested with `' OR '1'='1` and `'; DROP TABLE users; --` |
| CSRF | Spring Security CSRF token in every form, including all admin actions |
| Session fixation | the session id changes at login (`changeSessionId`) |
| Session theft | cookie is HttpOnly, SameSite=Lax, Secure in production; logout invalidates the session |
| Finding valid emails | same message for wrong password and unknown email; "disabled" only after the correct password; locks work for any email |
| XSS | Thymeleaf escapes all output; CSP `default-src 'self'` blocks inline scripts |
| Clickjacking | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` |
| Faked IP | proxy headers are only trusted from Cloudflare/trusted proxies |
| Privilege escalation | no role field at registration; `/admin/**` needs ADMIN |
| Admin mistakes | audit log; no self-disable, no blocking of own IP |
| Error leakage | custom error pages, stack traces never shown |
| Leaked passwords | breach check with k-anonymity |
| Secrets in Git | `.env` is git-ignored; secrets come from environment variables |

## 14. Configuration

Everything is in `application.properties` and can be changed with environment variables (or a local
`.env` file):

| Setting | Default | Variable |
|---|---|---|
| Rule 1 failures | 5 | MAX_FAILED_ATTEMPTS |
| Window | 10m | MONITORING_WINDOW |
| First lock / block | 15m | BLOCK_DURATION |
| Rule 2 accounts | 4 | IP_MAX_ACCOUNTS |
| Rule 3 failures | 10 | IP_MAX_FAILURES |
| Rule 4 failures / IPs | 8 / 3 | ACCOUNT_MAX_FAILURES / ACCOUNT_MIN_IPS |
| Rule 5 repeat blocks | 1h,24h | REPEAT_BLOCK_DURATIONS |
| Location lookup / breach check | on | IP_LOOKUP_ENABLED / BREACH_CHECK_ENABLED |
| Keep attempts | 180d | ATTEMPT_RETENTION |
| Display time zone | UTC | DISPLAY_TIMEZONE (Asia/Kolkata on Render) |

The values are bound to Java records with `@ConfigurationProperties` (for example
`LoginSecurityProperties`), so the rules read `properties.maxFailedAttempts()` instead of hard-coded
numbers.

## 15. Testing

`./mvnw test` runs 106 tests in about a minute. They use an in-memory H2 database in MySQL mode, so no
MySQL server is needed, and the outside services are switched off or mocked.

Three things make the tests possible:

- **A test clock.** Every service asks a `Clock` bean for "now". In tests it is `MutableClock`, so
  `clock.advance(Duration.ofMinutes(15))` tests "after 15 minutes" instantly.
- **Choosing the client IP.** `fromIp("192.168.1.10")` sets the request's remote address in MockMvc,
  so I can act as several computers.
- **The real login form.** Tests post to `/login` with a CSRF token, exactly like a browser.

| Test class | Tests | What it checks |
|---|---|---|
| LoginProtectionRulesTest | 18 | every rule end to end, shared Wi-Fi, rolling window, expiry, escalation, allow-list, ban |
| LoginFlowTest | 12 | success, wrong password, generic message, disabled account, session fixation, logout |
| ClientIpResolverTest | 11 | Render header, spoofing ignored, trusted proxies, IPv6, no DNS lookups |
| UserSecurityTest | 10 | device stored, banner, risk flags, sign out others, This wasn't me, password change, breach check |
| AdminDashboardTest | 8 | 403 for users, real counts, feed API, filters, CSV, IP page, no hashes on pages |
| AdminActionsTest | 8 | block/unblock/ban, safety checks, allow-list, disable user, unlock, CSRF |
| SimulatorServiceTest | 7 | each scenario fires its rule, clear removes only simulated rows |
| LoginPageStatusTest | 5 | counter survives refresh, countdown, disabled button, network warning |
| RegistrationTest | 5 | BCrypt hash, USER role, duplicate email |
| CsrfProtectionTest | 8 | CSRF on every form, old forms handled with a clear message, security headers |
| HelpersTest | 5 | User-Agent parser, private IPs, flags, CIDR validation, escalation |
| AdminInitializerTest | 3 | admin account created/repaired at startup, admin email cannot be registered |
| SqlInjectionTest | 3 | injection input stays plain text |
| BreachedPasswordServiceTest | 2 | k-anonymity parsing, fail-open |
| LoginAttemptServiceConcurrencyTest | 1 | 20 parallel failures from one IP create exactly one block |

Besides the automated tests I ran the app against a real MySQL 8 server, upgraded a database created
by version 1, and went through every page in a browser (the screenshots in `screenshots/` come from
that run).

## 16. Limitations and next steps

- **One instance only.** The failure lock and the sessions are in memory. Several instances would need
  a database or Redis lock, and a restart signs everyone out.
- **Approximate location.** It comes from the IP address and a free service.
- **User-Agent can be faked.** Device and "automated tool" are hints, not proof.
- **No e-mail.** Render's free plan blocks SMTP, so alerts are shown in the app instead of e-mailed.
- **No CAPTCHA or 2FA.** Rule 1 uses a short lock instead.
- **Registration says "already registered"**, which reveals that an email exists. E-mail verification
  would fix this.
- **ddl-auto=update** instead of a migration tool like Flyway.

Next I would add two-factor authentication (TOTP apps), e-mail alerts through an HTTP e-mail API,
Cloudflare Turnstile as a CAPTCHA before the Rule 1 lock, and Flyway migrations.

## 17. Numbers to remember

- Rule 1: **5** failures, one account + one IP, **10** minutes, lock **15** minutes
- Rule 2: **4** different accounts from one IP -> IP blocked
- Rule 3: **10** failures from one IP -> IP blocked
- Rule 4: **8** failures from **3+** IPs -> account locked for new IPs (known = used in last **90** days)
- Rule 5: **15 min -> 1 h -> 24 h** within **24** hours
- Risk: after failures 3, new country 2, VPN 2, automated 2, new device 1; alert at **2**
- **8** tables, **106** tests, attempts kept **180** days, location cache **30** days
- Breach check sends **5** characters of a SHA-1 hash
