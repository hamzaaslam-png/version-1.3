# Free Hosting Guide — Google Cloud Run + Neon (Postgres)

Aapka app free me online hoga: **Cloud Run** (app chalata hai) + **Neon** (data save karta hai).
Dono free. Niche har step copy-paste ke saath.

> Har jagah `YOUR-...` ko apni value se badlein.

---

## STEP 0 — Jo cheezein chahiye
- Google Cloud account (aapke paas hai) with **billing enabled** (free tier ke liye bhi card add karna parta hai — paisa nahi katega).
- Apna OAuth client (jo pehle se bana hua hai — `google_client_id` / `google_client_secret`).

---

## STEP 1 — Neon free database banayein (5 min)
1. https://neon.tech kholein → **Sign up** (Google se).
2. **Create project** → koi naam (e.g. `admob-tool`). Region apne paas wala chunein.
3. Project bante hi ek **Connection string** milega. "Connection Details" me se **`psql`/URI** copy karein. Woh aisa dikhega:
   ```
   postgresql://user:PASSWORD@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require
   ```
4. Is URL me `postgresql://` ko **`postgresql+psycopg2://`** se badal dein (SQLAlchemy driver):
   ```
   postgresql+psycopg2://user:PASSWORD@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require
   ```
   Yeh aapka **DATABASE_URL** hai — sambhal kar rakhein.

---

## STEP 2 — Ek strong secret_key banayein
PowerShell me:
```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```
Output (lamba random string) copy karein — yeh **SECRET_KEY** hai. (Ek hi baar banayein; baad me na badlein.)

---

## STEP 3 — gcloud install + login
1. Google Cloud CLI install karein: https://cloud.google.com/sdk/docs/install
2. PowerShell restart karke:
```powershell
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com
```
`YOUR_PROJECT_ID` aapke Google Cloud Console ke top par dikhता hai.

---

## STEP 4 — Pehli baar deploy (URL lene ke liye)
Project folder me (jahan `Dockerfile` hai) yeh chalayein:
```powershell
gcloud run deploy admob-tool `
  --source . `
  --region asia-south1 `
  --allow-unauthenticated `
  --memory 512Mi
```
- `asia-south1` = Mumbai (apne paas region chunein).
- Build + deploy ho jaane par ek **Service URL** milega, e.g.:
  ```
  https://admob-tool-xxxxxxxx-el.a.run.app
  ```
  Ise copy karein → yeh aapke app ka public link hai.

---

## STEP 5 — Google OAuth me production redirect URI add karein
1. Google Cloud Console → **APIs & Services → Credentials** → apna OAuth client kholein.
2. **Authorized redirect URIs** me add karein (STEP 4 wala URL + `/auth/callback`):
   ```
   https://admob-tool-xxxxxxxx-el.a.run.app/auth/callback
   ```
3. **Save**.
4. (Agar OAuth consent screen "Testing" me hai) → **Test users** me woh email add karein jo login karenge. (Testing mode me login to chalega par refresh token 7 din me expire hota hai.)

---

## STEP 6 — Env vars set karke dobara deploy (final)
Ab saare secrets + production settings ke saath deploy karein. Ek hi command:
```powershell
gcloud run deploy admob-tool `
  --source . `
  --region asia-south1 `
  --allow-unauthenticated `
  --memory 512Mi `
  --set-env-vars "google_client_id=YOUR_CLIENT_ID" `
  --set-env-vars "google_client_secret=YOUR_CLIENT_SECRET" `
  --set-env-vars "google_redirect_uri=https://YOUR-SERVICE-URL/auth/callback" `
  --set-env-vars "secret_key=YOUR_STRONG_SECRET_KEY" `
  --set-env-vars "database_url=postgresql+psycopg2://USER:PASS@HOST/DB?sslmode=require" `
  --set-env-vars "cookie_secure=true" `
  --set-env-vars "debug=false"
```

> Tip: agar value me comma (`,`) ho to `--set-env-vars` toot sakta hai. Aisa ho to har var ko alag `--update-env-vars` se set karein, ya `^` delimiter use karein.

---

## STEP 7 — Test
- Service URL browser me kholein → **Sign in with Google** → login → Sync AdMob → kaam karein.
- Doosra banda bhi usi link par apne Google account se login karke apna data use kar sakta hai.

---

## Zaroori baatein
- **secret_key kabhi na badlein** deploy ke baad — warna purane encrypted tokens/creds undecryptable ho jayenge (sabko dobara login + creds dalna parega).
- **`.env` aur `*.db` kabhi git/image me na jaayein** — `.dockerignore` already inhe block karta hai.
- **403 PERMISSION_DENIED** ka deployment se koi taalluq nahi — woh AdMob account ki mediation permission ka masla hai (alag).
- Neon DB use na ho to "so" jata hai; agla request usse ~1s me jaga deta hai (free plan — normal).
- Cost: Cloud Run + Neon dono free tier me — normal use par $0.
