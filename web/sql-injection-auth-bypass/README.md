# Login Bypass — Write-up

> **Platform:** HackTheBox  
> **Category:** Web  
> **Difficulty:** Easy  
> **Points:** 200  
> **Date:** 2024-11-03  
> **Author:** [Samson Ram](https://github.com/samram77-art)

---

## Challenge Description

> *A company's internal dashboard is only accessible to admins. We found a login page — can you get in?*

Connection string: `http://challenge.htb/login`

No source files were provided. Black-box challenge.

---

## Reconnaissance / Initial Analysis

First things first — I added `challenge.htb` to `/etc/hosts` pointing at the challenge IP and opened it in Firefox with Burp Suite running in the background.

The landing page is a simple login form with two fields: `username` and `password`, and a submit button labelled **"Login"**. The page title is "Admin Portal — Internal Use Only." There's nothing else visible. No registration link, no "forgot password", no OAuth buttons.

### Viewing Page Source

```html
<form method="POST" action="/login">
  <input type="text"     name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
```

Clean and minimal. No JavaScript validation on the client side. The form POSTs directly to `/login` — all logic is server-side.

### Testing Normal Input

I threw in `admin` / `admin` and `admin` / `password`. Both returned a terse `Invalid credentials.` message with no stack trace or verbose error. HTTP 200 on failure, which tells me the server isn't crashing — but that doesn't mean it's not injectable.

### Identifying the Attack Surface

The `username` field is the natural first target. Password fields tend to be hashed before comparison, making injection there less reliable. My hypothesis: the backend is doing something like:

```sql
SELECT * FROM users WHERE username = '[input]' AND password = '[hashed_input]';
```

If the `username` value is interpolated directly into the query without sanitisation, we have a classic SQLi entry point.

---

## Vulnerability Identified

**Vulnerability:** SQL Injection — Authentication Bypass  
**Location:** `username` parameter in `POST /login`  
**Confirmed by:** Application behaviour change on injection characters

The first sign came when I submitted a single quote (`'`) as the username. Instead of `Invalid credentials.`, the response returned a generic 500 error page. That's the tell — the application tried to execute a malformed SQL query and choked. The backend is almost certainly building its query via string concatenation.

---

## Exploit Development

### Attempt 1 — Classic OR 1=1

```
username: ' OR 1=1--
password: anything
```

**Result:** Logged in as the *first* user in the database — but it wasn't the admin account. The dashboard showed a regular user's panel, no flag visible.

### Attempt 2 — Targeting admin Specifically

I needed to target the `admin` row specifically. Tried:

```
username: admin'--
password: anything
```

**Result:** This time I landed on what looked like an admin panel. The URL changed to `/dashboard` and there was a "Welcome, admin" message. But the flag wasn't on this page — I needed to dig around.

### Attempt 3 — OR with String Equality

```
username: ' OR 'x'='x
password: anything
```

**Result:** Same as Attempt 1 — lands on first user. Too broad.

### Working Exploit — Inline Comment After Admin Username

The cleanest payload turned out to be:

```
username: admin' -- 
password: [blank]
```

Note the trailing space after `--`. MySQL requires a space (or another character) after `--` for it to be treated as a comment. This collapses the query to:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = '';
```

Everything after `--` is commented out. The password check is completely eliminated. The query returns the `admin` row unconditionally, and the application logs us in.

### Burp Suite — What I Saw

In the Burp Proxy HTTP history, the successful request looked like:

```
POST /login HTTP/1.1
Host: challenge.htb
Content-Type: application/x-www-form-urlencoded

username=admin'+--+&password=
```

The response was a `302 Found` redirecting to `/dashboard`. In the response body (before the redirect) and in the subsequent `/dashboard` GET, I found the flag embedded in a `<div class="flag">` element.

---

## Flag

```
HTB{sql_1nj3ct10n_1s_cl4ss1c}
```

---

## Lessons Learned

1. **Client-side validation is not security.** The form had no JavaScript validation, but even if it did, Burp Suite bypasses it trivially. Security must be enforced server-side.
2. **Error messages are intelligence.** The 500 response on a single `'` confirmed injection before I even crafted a real payload. Production apps should return generic error pages without leaking database errors.
3. **OR 1=1 is noisy.** Targeting a specific username (`admin'--`) is cleaner and less likely to trip anomaly detection than a blanket true condition.

## Remediation

The fix is straightforward — use **parameterised queries** (prepared statements). Instead of:

```python
# Vulnerable
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

Use:

```python
# Safe
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, hashed_password))
```

With parameterised queries, the database driver handles escaping. The user input is *never* interpreted as SQL syntax — it's always treated as a literal value. Additionally:

- Implement account lockout after N failed attempts to slow brute-force and injection probing.
- Run the application database user with least-privilege — read-only access to only the tables it needs.
- Log authentication failures with the input that caused them (sanitised for display) to aid incident detection.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Burp Suite Community](https://portswigger.net/burp/communitydownload) | Intercepting and replaying HTTP requests, inspecting responses |
| Firefox | Manual browser testing |
| `curl` | Quick payload testing from the command line |

---

## References

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy — SQLi](https://portswigger.net/web-security/sql-injection)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
