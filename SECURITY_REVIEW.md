# Secure Coding Review — Findings & Remediation (Python)

**Scope:** `vulnerable_app/app.py` (Flask)  
**Method:** Manual review (OWASP/CERT) + conceptual SAST

## Findings
- F1 SQL Injection: string-formatted query in /login → Use parameterized SQL; hash passwords.
- F2 Command Injection: shell=True in /exec → Avoid shell, validate, use shlex.split.
- F3 Path Traversal: /read accepts raw filename → secure_filename + base dir check.
- F4 Code Injection: eval(user input) in /calc → remove eval; build safe parser.
- F5 Unsafe Deserialization: pickle.loads on untrusted data in /loads → replace with JSON; sign/verify.
- F6 Hardcoded Secret: SECRET_KEY in code → move to environment or secret manager.
- F7 Debug Mode: debug=True → disable in production.
- F8 Missing CSRF/session hardening → add CSRF tokens, secure cookies, HTTPS.
