# Test Execution Evidence — SecureAuth

> **Integrity Notice:** This file provides the execution commands and evidence capture template. Do not record `PASSED` counts until you execute `pytest -v` in your local Python virtual environment.

---

## 1. Environment & Execution Commands

```powershell
# Run from task-2-secure-authentication/ in Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
```

---

## 2. Recorded Execution Log

**Execution Status:** Pending local run *(authoring environment contained Python 3.11.2 stdlib without `pip`/Flask installed; Python syntax and AST verification completed cleanly across all modules and test files)*.

Paste your local `pytest -v` terminal output below after running the suite:

```text
# Run `pytest -v` locally and paste the real output here
```

---

## 3. Manual Browser Verification Checklist

After starting the app (`python run.py`), verify these behaviors manually:

- [ ] Register a new account via `http://127.0.0.1:5000/register` and confirm weak passwords are rejected.
- [ ] Sign in at `http://127.0.0.1:5000/login` and verify DevTools → Application → Cookies shows `HttpOnly` and `SameSite=Lax` on `secureauth_session`.
- [ ] Submit 6 failed logins rapidly and confirm the `Too many attempts` (`429`) page appears.
- [ ] Visit `/dashboard` while signed out and confirm automatic redirect to `/login`.
- [ ] Click **Sign Out** and verify browser Back/refresh on `/dashboard` redirects to `/login`.
