# Credential-Stuffing Defense for a Login Service

Bethany, Elian, Samuel, Shristy

Group 6 project for Intro to Information Security and Privacy. One small login app, one attack script, and a few defenses. The vulnerable and protected versions are the same app behind a `PROTECTED` switch, not two separate builds.

## Group Personalization Seed

Sum of all 4 members' last-2 student-ID digits, mod 15 = **4**

What this number controls: *TBD, update this once the group decides.*

## Routes

| Route | Method | What it does |
|---|---|---|
| `/signup` | POST | Creates a user. Fields: `email`, `emailConfirmation`, `username`, `password`, `passwordConfirmation` |
| `/login` | POST | Checks a username/password. Fields: `username`, `password` |
| `/changepass` | POST | Updates a password. Fields: `username_or_email`, `oldPassword`, `newPassword` |
| `/signup-page.html` | GET | Signup form |
| `/login-serv-vuln1.html` | GET | Login form |
| `/change-pass.html` | GET | Change-password form |

## Setup (do this once per computer)

```bash
git clone https://github.com/<owner>/Credential-Stuffing-Defense-Login.git
cd Credential-Stuffing-Defense-Login

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Seed the database (do this once per computer)

This creates `users.db` with 20 fake users plus one deliberately weak account (`weakuser`), used for the Mandatory Failure Case.

```bash
python app/seed.py
```

You should see `db seeded!` printed. `users.db` is in `.gitignore` on purpose, so it stays local to your machine and never gets pushed.

If you ever change the seeded passwords, delete and reseed:

```bash
rm users.db          # Windows: Remove-Item users.db
python app/seed.py
```

## Run the server

From the project root (not inside `app/`):

```bash
uvicorn app.main:app --reload
```

Then open one of these in a browser:

- `http://127.0.0.1:8000/login-serv-vuln1.html`
- `http://127.0.0.1:8000/signup-page.html`
- `http://127.0.0.1:8000/change-pass.html`
- `http://127.0.0.1:8000/docs` (test any route by hand, no HTML needed)

### Quick checks

- Sign up a new user → "Account created"
- Sign up the same username again → "Username or Email already taken"
- Log in as that user → "Login successful"
- Log in with a wrong password → "Invalid credentials"
- Log in as `weakuser` / `pass131` → "Login successful"

If signup or login fails with a 500 error on a fresh clone, make sure `create_a_table()` runs on startup in `app/main.py` and that you've run the seed step above.

## Run the attack script

In a second terminal, with the server still running in the first:

```bash
python attack/stuff.py
```

This reads `attack/guesses.txt` (`username:password` pairs) and tries each one against `/login`. It prints each attempt and a summary:

```
HIT: weakuser:pass131
fail (401): user5:wrongguess
...
--- summary ---
attempts: 5
hits: 1
blocked (429): 0
time: 0.10s
```

A `HIT` means the login succeeded. `fail (401)` means wrong credentials. Once Phase 3 adds rate-limiting, repeated failures should start showing `BLOCKED (429)` instead of more fails.

To try your own guesses, edit `attack/guesses.txt`, one pair per line:

```
weakuser:welcome4
admin:admin123
```

## Project structure

```
Credential-Stuffing-Defense-Login/
├── README.md
├── requirements.txt
├── .gitignore
├── app/
│   ├── main.py         # FastAPI app, routes, db setup
│   └── seed.py         # Seeds users.db with fake + weak accounts
├── static/
│   ├── signup-page.html / signer.css
│   ├── login-serv-vuln1.html / logger.css
│   └── change-pass.html / change-pass.css
└── attack/
    ├── stuff.py        # Attack script
    └── guesses.txt     # Sample username:password pairs
```

## Status

- [x] Phase 1: Vulnerable login service
- [x] Phase 2: Attack script, confirmed hit on `weakuser`
- [ ] Phase 3: Defenses (rate limiting, lockout, breach check, logging)
- [ ] Phase 4: Testing the protected version
- [ ] Phase 5: Demo rehearsal
- [ ] Phase 6: Final report