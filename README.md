# Email Analyzer (Bootstrap-free theme)

A Django project with an `.eml` parser, DNS lookup, SPF/DMARC configuration check, and a Contact Us form stored in SQLite and available in Django Admin.

## Visual theme

- Shared CSS: `email_parser/static/email_analyzer/css/styles.css`
- Parser-only CSS: `email_parser/static/email_analyzer/css/parser/styles.css`
- DNS-only CSS: `dns_check/static/dns_check/css/styles.css`
- Spoof-check-only CSS: `spoof_check/static/spoof_check/css/styles.css`
- Bootstrap CSS/JavaScript dependencies have been removed. The responsive navigation toggle is handled by small custom JavaScript in `base.html`.

## Run on Windows PowerShell

1. Extract the ZIP and open PowerShell in the folder that contains `manage.py`.
2. Create the virtual environment and install packages with the virtual environment's Python executable:

   ```powershell
   py -m venv venv
   .\venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

   **Activation is optional.** If PowerShell blocks `Activate.ps1`, do not change system-wide execution policy; continue to use ` .\venv\Scripts\python.exe` for the commands below.

3. Copy `.env.example` to `.env`, then set `DJANGO_SECRET_KEY` to a long random value. For a simple PowerShell copy, run `Copy-Item .env.example .env`.
4. Create database tables and run checks/tests:

   ```powershell
   .\venv\Scripts\python.exe manage.py migrate
   .\venv\Scripts\python.exe manage.py check
   .\venv\Scripts\python.exe manage.py test
   ```

5. Start the development server:

   ```powershell
   .\venv\Scripts\python.exe manage.py runserver
   ```

6. Open <http://127.0.0.1:8000/>.

To create an admin account, run:

```powershell
.\venv\Scripts\python.exe manage.py createsuperuser
```

Then visit <http://127.0.0.1:8000/admin/>. Contact form messages are stored in the database and listed in the Email Parser admin section.

## VirusTotal scanning

Email parsing and header extraction work without a VirusTotal key. To enable URL/attachment reputation lookups, add your own key to `.env`:

```dotenv
VIRUSTOTAL_API_KEY=your_real_virustotal_api_key
```

Restart Django after changing `.env`. Without a key, scanning returns an explanatory message rather than sending requests with a placeholder key.

## Spoof check

SPF and DMARC TXT records are looked up through `dnspython`; the older `emailprotectionslib` dependency has been removed because its installed package could fail while importing `Resolver`. The page provides a simplified domain-configuration indicator, not a guarantee that any particular email cannot be spoofed.

## Notes

- This ZIP does not include `db.sqlite3`, local virtual environments, or Python bytecode caches. Run migrations to create a fresh database. Existing admin accounts and saved contact messages from another project folder will not be transferred.
- Keep `.env` private and never commit a real secret key or VirusTotal key to GitHub.
- Do not deploy with `DJANGO_DEBUG=True` or a placeholder `DJANGO_SECRET_KEY`. Configure allowed hosts, HTTPS, and static files for your hosting provider.
- DNS, IP-geolocation, and VirusTotal results depend on network availability and API limits. Uploaded `.eml` files are limited to 10 MB. Only inspect email files you are authorized to analyze.

## Deploy online

See [README_DEPLOY_RENDER.md](README_DEPLOY_RENDER.md) for step-by-step deployment using Render for the web app and Neon PostgreSQL for persistent data. The deployment config uses environment variables for secrets and does not rely on a hosted SQLite file.
