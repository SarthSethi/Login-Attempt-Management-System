# LAMS - Viva Questions

Questions I expect, with the answers I would give. Grouped by topic. For details see PROJECT_GUIDE.md.

## 1. About the project

**What is your project?**
A login website (Spring Boot + MySQL) that records every login attempt and defends against password
attacks with five layered rules. It stores the IP, location, device and result of every attempt,
alerts the admin, and lets users see their own login history and report logins that were not them.

**Which attacks does it handle?**
Brute force on one account, credential stuffing (leaked passwords tried on many accounts), distributed
attacks from many IPs, and account takeover (the attacker gets the password right).

**What was wrong with the simple "block an IP after 5 failures" idea?**
Three things. Many people share one public IP, so one person's typos block a whole college network.
An attacker who changes IP or uses a botnet is never stopped. And a guessed password is never noticed,
because only failures were counted.

**Who would use this?**
Any small website with user accounts, for example a college portal. The admin watches the dashboard;
users get a security page for their own account.

**What is new or different compared with a normal login page?**
The block check runs before the password check, the rules look at three angles (account+IP, IP,
account), successful logins are risk-checked, the real visitor IP is detected behind Cloudflare, and
there is a full monitoring dashboard with an attack simulator.

## 2. The rules

**Explain Rule 1.**
5 failures for one email from one IP within 10 minutes lock that email for that IP for 15 minutes.
Only that pair is locked. Other accounts on the same IP and the same account on other IPs still work.

**Why lock the pair and not the IP?**
Because of shared IPs. A whole hostel or college network often has one public IP. Locking the pair stops
the guessing without punishing everyone else.

**Then what stops someone trying 4 guesses on each of many accounts?**
Rule 2 (4 different accounts failing from one IP blocks the IP) and Rule 3 (10 failures from one IP
block the IP).

**What is credential stuffing and which rule catches it?**
Attackers take email/password pairs leaked from another website and try them here, because people
reuse passwords. It looks like one IP trying many different accounts once each, which is Rule 2.

**Explain Rule 4.**
8 failures for one email from at least 3 different IPs within 10 minutes means a distributed attack.
The account is then locked for 15 minutes, but only for IPs the owner has never logged in from in the
last 90 days.

**Why not lock the account completely in Rule 4?**
Then an attacker could lock any user out on purpose just by typing wrong passwords for their email.
That would be a denial-of-service. Refusing only new IPs stops the botnet but lets the real owner in
from their usual network.

**Explain Rule 5.**
If the same IP is blocked again within 24 hours, the block gets longer: 15 minutes, then 1 hour, then
24 hours. I count earlier automatic blocks in `BlockedIpService.blockAutomatically`.

**What is the allow-list?**
A list of trusted IPs or CIDR ranges, for example the college network. Rules 2, 3 and 5 never block
them. Rules 1 and 4 still apply, because they protect accounts.

**What is a rolling window?**
I count attempts with `attempted_at > now - 10 minutes`. As time passes, old failures fall out of the
window automatically. There is no fixed "every 10 minutes" reset.

**How does a block end?**
Each block has `expires_at`. A block is active only while `expires_at > now`. There is no job that
deletes it; the row stays as history.

**Are failures that caused a block counted again after it ends?**
No. The counting starts from the later of "10 minutes ago" and the time of the last block (or lock).
Otherwise the IP would be blocked again by the same old failures right after the block ends.

**Does a successful login reset the counter?**
For Rule 1, yes: the pair is counted from its last success. For the IP rules and Rule 4, no, otherwise
an attacker could reset the counter by logging in to their own account.

**Is a request from a blocked IP checked for the password?**
No. My filter runs before Spring Security's login filter and stops the request. Even the correct
password is refused, so guessing is useless during the block.

**Does a blocked request extend the block?**
No. It is saved as BLOCKED but `expires_at` is not changed, otherwise a script could keep an IP blocked
forever and the block would never end for a real user behind it.

**What happens with an empty email or password?**
It is not counted, because it is not a password guess.

**Why do locks work for emails that do not exist?**
If only real accounts could be locked, an attacker could find out which emails are registered by
looking at which ones get locked.

## 3. Successful logins and risk

**How do you detect a stolen password if the login succeeds?**
I compare the login with the user's earlier successful logins and give points: after failed attempts
3, new country 2, VPN or data centre 2, automated tool 2, new device 1. A score of 2 or more raises an
alert. The user sees the flags on their own page.

**Why is "after failed attempts" worth the most?**
A success right after several failures is exactly what a successful guess looks like.

**How do you know the country?**
From the free ip-api.com service. Each IP is looked up once and cached in `ip_info`. Private IPs are
recognised locally.

**How do you know the device?**
From the User-Agent header, with my own small parser (`UserAgentParser`). It finds the browser, OS and
whether it is desktop, mobile, tablet or a script like curl, Python or Hydra.

**Can the User-Agent be faked?**
Yes, so I use it only as a hint for risk flags, never as proof.

**What does "This wasn't me" do?**
It signs out the user's other sessions, blocks the IP of that login for 24 hours (unless it is the
user's current IP or trusted), raises an alert for the admin, and opens the change password page.

## 4. IP address detection

**How do you get the visitor's IP?**
`ClientIpResolver`. On Render I read `CF-Connecting-IP`. Behind another trusted proxy I read
`X-Forwarded-For` from right to left. Otherwise I use the TCP connection address.

**Why not just use `request.getRemoteAddr()`?**
On Render that is the address of Render's internal proxy, not the visitor. In my first version this
made all the stored IPs wrong.

**Why not just read X-Forwarded-For?**
A visitor can put anything in it, for example a random IP to dodge the block. Proxies only append to
it. So I only trust it from my own proxies and read it from the right.

**Why is CF-Connecting-IP safe?**
Cloudflare sits in front of every Render service and always overwrites that header with the real
visitor IP, so a value sent by the visitor is replaced.

**How did you check it works on the live site?**
The Connection Check panel on the admin overview shows the detected IP, the method and the headers. I
compared it with "what is my IP".

**Do you support IPv6?**
Yes. Addresses are normalised (for example `::1` becomes `0:0:0:0:0:0:0:1`) so the same client always
has the same text. The column is 45 characters long, enough for IPv6.

## 5. Spring and Java

**What does Spring Security do in your project?**
Form login, BCrypt password checking, CSRF tokens, session handling, logout and the ADMIN role check.
I add my own filter and my own success/failure handlers.

**What is a filter chain?**
A list of filters every request passes through before it reaches a controller. Each filter can stop the
request. Mine is `LoginProtectionFilter`, placed before `UsernamePasswordAuthenticationFilter`.

**Why is your filter not a @Component?**
Spring Boot registers every Filter bean as a normal servlet filter too. It would then run outside the
Spring Security chain, before the CSRF check. So I create it with `new` in `SecurityConfig`.

**What is `UserDetailsService`?**
The interface Spring Security uses to load a user. My `CustomUserDetailsService` loads the user by
email from MySQL and returns the hash, role and enabled flag.

**What are the success and failure handlers?**
Hooks Spring Security calls after the password check. My failure handler saves the attempt and applies
the rules; my success handler saves the attempt with risk flags and decides where to redirect.

**What is dependency injection here?**
Services get their dependencies through the constructor, for example `LoginProtectionService` receives
the repositories and other services. Spring creates and connects the objects.

**What is `@Transactional`?**
It runs a method in one database transaction. All changes are committed together or rolled back. The
failure processing runs inside one transaction (`TransactionTemplate`).

**What is `@ConfigurationProperties`?**
It binds settings like `app.security.max-failed-attempts` to a Java record, so the rules use
`properties.maxFailedAttempts()` instead of hard-coded numbers.

**Why do you have a Clock bean?**
Every service asks it for "now". Tests replace it with a clock they can move forward, so "after 15
minutes" is tested instantly.

**What is `@Scheduled` used for?**
The background IP location lookup (every 15 seconds) and the nightly clean-up of old attempts.

**What are Java records?**
Short immutable classes, for example `LoginStatus` and the property classes. Java writes the
constructor, getters, equals and toString.

## 6. Database

**Which tables do you have?**
users, login_attempts, blocked_ips, account_locks, security_alerts, ip_info, ip_allowlist and
admin_actions.

**Why no foreign keys?**
Attempts are stored even for emails without an account and for IPs that were never blocked. The links
are logical (by email or IP), not enforced.

**Which indexes and why?**
`(ip_address, attempted_at)` for counting failures of an IP in the window, `(attempted_email,
attempted_at)` for the account rules, `(outcome, attempted_at)` for dashboard counts,
`(ip_address, expires_at)` for "is this IP blocked now".

**Who creates the tables?**
Hibernate, with `ddl-auto=update`. When I added version 2 it added the new tables and columns to the
existing Aiven database without losing data.

**Why store times in UTC?**
So comparisons are always correct no matter where the server runs. I convert to Indian time only when
showing them (`DateDisplay`).

**How do you prevent SQL injection?**
I only use Spring Data derived queries and JPQL with named parameters, so user input is always sent as
a bound parameter, never concatenated into SQL. A test sends `' OR '1'='1` and `'; DROP TABLE users; --`.

**How big can the table get?**
Attempts older than 180 days are deleted every night. 180 days matches CERT-In's direction on keeping
logs.

## 7. Security

**How are passwords stored?**
As BCrypt hashes. BCrypt adds a random salt and is deliberately slow, so a stolen database cannot be
cracked quickly. The plain password is never stored or logged.

**Why does BCrypt have a 72-byte limit and how do you handle it?**
BCrypt only uses the first 72 bytes. I reject longer passwords at registration (non-English characters
take more than one byte each).

**How does the breach check work without sending the password?**
SHA-1 hash of the password, send only the first 5 hex characters, get back all leaked hashes that start
with them, compare the rest locally. This is k-anonymity.

**What if Have I Been Pwned is down?**
The password is accepted (fail-open), so registration never breaks.

**What is CSRF and how is it handled?**
A malicious site making the user's browser send a request to my site. Spring Security puts a secret
token in every form and rejects requests without it. All admin actions are POST forms with the token.

**Why could a correct password show "403 Access Denied" at first?**
The CSRF check runs before the password check. Its token is stored in the session, so a login page
from a session that no longer exists (the app restarted or the free Render instance woke up, or the page
was open for more than 30 minutes) or from another tab (signing in or out there replaces the token) was
refused with Spring's default 403 page. I added `CsrfFailureHandler`: the request is still refused, but
the user goes back to the login page with the email filled in and the message "The page had expired, so
your password was not checked". CSRF protection is unchanged.

**What is session fixation?**
An attacker gives the victim a known session id before login. I change the session id at login.

**How do you prevent XSS?**
Thymeleaf escapes everything with `th:text`, the Content-Security-Policy allows only my own scripts, and
the live feed builds rows with `textContent`.

**How do you stop people finding out which emails are registered?**
Same message for unknown email and wrong password, "disabled" only after the correct password, and
locks for any email. (Registration still says "already registered", which is a known limitation.)

**Can a normal user open the admin panel?**
No, `/admin/**` needs the ADMIN role and returns 403. Registration has no role field.

**How is the admin account created?**
At startup from the environment variables `ADMIN_EMAIL` and `ADMIN_PASSWORD` (`AdminInitializer`).

**What is CSV injection?**
A cell starting with `=` can run as a formula in Excel. I prefix such cells with `'` in the export.

## 8. Features

**What does the admin overview show?**
Summary cards, activity chart (24 h or 7 days), top attacking IPs, most targeted accounts, attempts by
country, open alerts, currently blocked IPs, a live feed, the active rules and the connection check.

**How does the live feed work?**
JavaScript asks `/admin/api/feed?after=<last id>` every 5 seconds and adds new rows.

**How are the charts drawn?**
`StatsService` puts attempts into hourly or daily buckets and calculates SVG rectangles. No chart
library, so the CSP stays strict.

**What is the attack simulator?**
A demo tool that sends made-up attempts through the real rule methods. It uses reserved documentation
IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) and marks everything as simulated so it can be cleared.

**How does "sign out other devices" work?**
Spring Security's `SessionRegistry` knows all sessions. I call `expireNow()` on the others and the
`ConcurrentSessionFilter` logs them out on their next request.

**Why does the login counter not reset when I refresh?**
The page reads it from the database for the email and IP every time it opens. The typed email is kept
in the visitor's session.

## 9. Testing

**How did you test the project?**
106 automated tests with JUnit 5 and MockMvc, plus a run on real MySQL 8 and a browser walkthrough.

**How do you test "15 minutes later" without waiting?**
A `MutableClock` replaces the real clock in tests; `clock.advance(Duration.ofMinutes(15))`.

**How do you test different IPs?**
MockMvc lets me set the remote address of each request (`fromIp(...)`).

**How do you test concurrency?**
20 threads send failures from one IP at the same moment; the test checks exactly one block is created.

**Which database do the tests use?**
H2 in memory in MySQL mode, so they run anywhere. I also ran the app on real MySQL.

**How do you test the outside services?**
They are switched off in tests and replaced by Mockito mocks where needed, for example a mocked breach
count of 123,456.

## 10. Deployment

**Where is it deployed?**
The app runs as a Docker container on Render (free plan), the database is MySQL on Aiven (free plan).

**Why not Render's database?**
Render's free database is PostgreSQL only; the project needs MySQL.

**How are secrets handled?**
As environment variables in Render (database password, admin password). The local `.env` file is
ignored by Git.

**Why is the first page slow?**
The free Render service sleeps after 15 minutes without traffic and takes about a minute to wake up.

**Why no e-mail alerts?**
Render's free plan blocks outgoing SMTP. E-mail would need an HTTP e-mail API; it is future work.

## 11. Limitations and future work

**What are the limitations?**
One instance only (in-memory lock and sessions), approximate location, User-Agent can be faked, no
e-mail, no CAPTCHA or 2FA, registration reveals taken emails, Hibernate update instead of Flyway.

**What would you add next?**
Two-factor authentication, e-mail alerts, a CAPTCHA before the Rule 1 lock, Flyway migrations, and a
shared lock (database or Redis) so several instances can run.

**How would you scale it to several servers?**
Move the failure lock to the database (`SELECT ... FOR UPDATE`) or Redis, and store sessions in the
database with Spring Session.
