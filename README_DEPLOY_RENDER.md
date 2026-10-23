# Deploy Email Analyzer to the web (Render + Neon)

This project can run locally with SQLite. For a hosted app, configure PostgreSQL through `DATABASE_URL`; Render's local filesystem/SQLite is not a reliable persistent production database.

## Recommended setup
- **Web app:** Render Web Service (free tier is suitable for a demo; services may sleep when idle).
- **Database:** Neon Postgres Free. Render's own Free Postgres currently expires after 30 days, so Neon avoids that specific expiry. Neon Free still has compute/storage/network limits, so keep backups of important data.
- **Source:** GitHub repository containing the contents of this project (the folder containing `manage.py`, `render.yaml`, and `build.sh`).

## 1. Push this project to GitHub
1. Create a new private or public repository on GitHub.
2. Upload the project contents, not the ZIP file itself. The repository root should contain `manage.py`, `requirements.txt`, `render.yaml`, and `build.sh`.
3. Never upload `.env`, `venv/`, `db.sqlite3`, API keys, passwords, or Django secret keys. `.gitignore` excludes the typical local secret/database/venv files.

## 2. Create a Neon PostgreSQL database
1. Sign up at https://neon.tech and create a project/database.
2. In its Connect dialog, choose Python or the connection string option and copy the PostgreSQL connection URL. Prefer the pooled connection string if offered; ensure SSL is enabled (commonly `sslmode=require`).
3. Keep this URL private. It contains database credentials.

## 3. Deploy on Render
1. Sign up at https://render.com and connect your GitHub account.
2. Use **New → Blueprint** and select the repository containing `render.yaml`, or create a **New Web Service** from that repository.
3. If using Blueprint, provide the `DATABASE_URL` value requested by the blueprint. If doing a manual Web Service, set:
   - Build command: `bash build.sh`
   - Start command: `gunicorn email_analyzer.wsgi:application --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
   - Environment variables before deployment:
     - `DJANGO_SECRET_KEY`: generate a unique secret in Render
     - `DJANGO_DEBUG`: `False`
     - `DATABASE_URL`: Neon connection string
     - `VIRUSTOTAL_API_KEY`: optional; add your key only if you want URL/attachment reputation lookups
   The app reads Render's `RENDER_EXTERNAL_HOSTNAME` automatically for `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`.
4. Let the build complete. `build.sh` installs dependencies, collects static CSS/JS, and runs migrations.
5. Open the `.onrender.com` URL shown in the Render dashboard.

## 4. Create your live admin login
For a new deployment, create an admin user against the same hosted database. The safest convenient path is to run the management command from an authenticated deployment shell if your Render plan provides it:

```bash
python manage.py createsuperuser
```

If your current Render plan doesn't include a shell, set up a one-time local connection to the same `DATABASE_URL` in a separate `.env` (do not commit it), run `python manage.py createsuperuser`, then remove the temporary URL from local `.env` when finished. Verify you are connecting to the intended hosted database before creating accounts.

Admin URL: `https://YOUR-APP.onrender.com/admin/`

## Notes and limitations
- Free Render web services may spin down after inactivity, so the first request can be slow.
- Neon Free has usage limits. Save/export important Contact Us records regularly.
- Do not set `DJANGO_DEBUG=True` on the public deployment.
- Never commit `.env` or expose `DATABASE_URL`, `DJANGO_SECRET_KEY`, or `VIRUSTOTAL_API_KEY`.
- Email analysis can involve external DNS and VirusTotal requests. Those can time out or be limited by external services.
- Uploading a real `.eml` file may disclose its contents to the external IP lookup/VirusTotal services used by analysis. Only test with files you are authorized to inspect.
