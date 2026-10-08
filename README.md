# CTI-Intel — AI-Assisted IOC Investigation Platform

MVP implementation for the Cyber Threat Intelligence capstone.

## Current implementation
- FastAPI backend
- PostgreSQL database
- IOC type detection and validation
- IOC normalization for IP addresses, domains, URLs, email addresses, and file hashes
- Mock threat-intelligence enrichment layer
- Correlation results for related indicators, malware, actors, campaigns, and ATT&CK techniques
- Explainable risk scoring with returned factors
- Gemini-powered analyst brief with a deterministic fallback when Gemini is unavailable
- Investigation API

## Run locally

### 1. Configure and start PostgreSQL (from the repository root)

Copy `.env.example` to `.env` and set `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` locally. The `.env` file is ignored by Git; use unique local values and do not commit it.

```bash
docker compose up -d postgres
```

Compose publishes PostgreSQL on host port `5433` and container port `5432`; this avoids colliding with a PostgreSQL server already listening on the host's `5432`. PostgreSQL keeps its data in the named `cti_pgdata` volume.

### 2. Configure the backend

From `backend`, copy `.env.example` to `.env` and set `DATABASE_URL` using the database values configured for Compose:

```dotenv
DATABASE_URL=postgresql+psycopg2://<user>:<password>@localhost:5433/<database>
```

The backend also reads `DATABASE_URL` from its process environment; that value takes precedence over `backend/.env`. Keep real credentials in local ignored environment files or a deployment secret store, not in source control.

For Gemini analysis, put your key only in the ignored `backend/.env` file as `GEMINI_API_KEY=...`. You may optionally set `GEMINI_MODEL`; the default is `gemini-3.8-flash`. Never put the key in frontend configuration or commit it. If the key is missing or Gemini is unavailable, investigations use the built-in deterministic analyst brief.

### 3. Create Python environment
```bash
cd backend
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Start API
```bash
uvicorn app.main:app --reload
```

Startup checks the database connection and creates any missing tables for the current MVP model. Open Swagger UI:
`http://127.0.0.1:8000/docs`

### 5. Verify health and investigate an IOC

Check API and database health:

```bash
curl http://127.0.0.1:8000/health
```

An available database returns `status`, `api`, and `database` as `healthy`. An unavailable database returns HTTP 503 and reports `database: unavailable`.

Submit a valid IOC:

```bash
curl -X POST http://127.0.0.1:8000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"value":"8.8.8.8"}'
```

The root endpoint is `GET /`. Swagger UI is also available at `http://127.0.0.1:8000/docs`.

Previous stored IOC investigations can be listed with `GET /api/investigations`. It returns the newest records first; an optional `limit` query parameter accepts values from 1 to 100 (default 20).

IOC submissions are trimmed and normalized before lookup and storage. Domains and hash values are lowercased; URL schemes and hosts are lowercased, default ports and fragments are removed, and an empty path is normalized to `/`. Supported types are IPv4, IPv6, domains, HTTP(S) URLs, email addresses, MD5, SHA1, and SHA256.

The enrichment records are synthetic demo examples. Each investigation response includes a risk score, priority, confidence, and a `factors` array explaining the score, along with correlation fields when demo associations are available.

## React dashboard

The Vite + React dashboard lives in `frontend` and uses `http://127.0.0.1:8000` as its default API base URL. FastAPI permits browser requests from the local Vite origins on port `5173`.

Run the backend first in one terminal:

```bash
cd backend
uvicorn app.main:app --reload
```

In a second terminal, install the frontend dependencies and start Vite:

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Enter an IPv4/IPv6 address, domain, URL, email address, or file hash and select **Investigate IOC**. The dashboard shows the score, priority, confidence, factors, correlations, indicators, and analysis summary. Investigation History loads from `GET /api/investigations`; selecting a row submits that IOC again to `POST /api/investigate` to load its full details.

To use another backend URL, copy `frontend/.env.example` to `frontend/.env.local`, edit `VITE_API_BASE_URL`, and restart Vite.

## Deployment Configuration

For Vercel, set `VITE_API_BASE_URL` to the deployed Render API base URL. The frontend keeps `http://127.0.0.1:8000` as its local-development fallback.

For Render, configure `DATABASE_URL` with the managed PostgreSQL connection string and `FRONTEND_ORIGIN` with the deployed Vercel site origin so browser requests pass CORS. `GEMINI_API_KEY` and `GEMINI_MODEL` are optional; without Gemini access, investigations continue with the deterministic analyst brief. Keep secret values in the cloud provider's environment settings, never in frontend variables, README, or committed files. `backend/.env.example` lists the backend variable names with blank placeholder values.

## PostgreSQL troubleshooting

1. From the repository root, run `docker compose ps` and confirm `cti-postgres` is running with host port `5433` mapped to container port `5432`.
2. Check the effective backend `DATABASE_URL`: process environment overrides `backend/.env`. Confirm database, user, host, and port without sharing the connection string.
3. Verify the role can log in without changing the database:

   ```bash
   docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -W -c "select current_user, current_database();"'
   ```

4. If credentials disagree, inspect the existing PostgreSQL role and reset only that role's password through an authorized PostgreSQL administrator session. Do not remove the `cti_pgdata` volume: Compose initialization variables only apply when PostgreSQL first initializes an empty data directory, and deleting the volume destroys its data.
5. Restart the backend after correcting the URL or role password, then confirm `/health` reports `database: healthy`.

### Example IOC request
POST `/api/investigate`
```json
{"value":"8.8.8.8"}
```

## Important
The enrichment layer currently uses deterministic demo data so the architecture can be tested without external services. Before final submission, replace it with authorized CTI sources/APIs and preserve source attribution in the database.
