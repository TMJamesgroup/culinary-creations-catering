import os, json, time, secrets
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import psycopg
from psycopg.types.json import Jsonb

app = FastAPI(title="Culinary Creations Inquiries", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["https://culinary-creations-catering.onrender.com"], allow_methods=["POST","GET"], allow_headers=["Content-Type","Authorization"])
DATABASE_URL=os.environ["DATABASE_URL"]
ADMIN_TOKEN=os.environ["ADMIN_TOKEN"]
_recent={}
class Inquiry(BaseModel):
    kind: str
    payload: dict
    website: str = ""
@app.get("/health")
def health():
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"ok":True,"database":"connected"}
    except Exception:
        raise HTTPException(503,"Database temporarily unavailable")
@app.post("/api/inquiries", status_code=201)
def submit(data:Inquiry, request:Request):
    if data.website: return {"accepted":True}
    if data.kind not in ("event","partner"): raise HTTPException(400,"Invalid form type")
    payload=data.payload
    if len(json.dumps(payload))>15000: raise HTTPException(413,"Too much data")
    required=["client","email"] if data.kind=="event" else ["business","contact","email","phone","details"]
    if any(not str(payload.get(k,"")).strip() for k in required): raise HTTPException(422,"Missing required fields")
    email=str(payload["email"]).strip()
    if len(email)>254 or "@" not in email or "." not in email.split("@")[-1]: raise HTTPException(422,"Invalid email")
    ip=request.client.host if request.client else "unknown"
    now=time.time()
    key=ip+":"+email.lower()
    if now-_recent.get(key,0)<5: raise HTTPException(429,"Please wait before submitting again")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO public.catering_inquiries(kind,payload) VALUES (%s,%s) RETURNING id",(data.kind,Jsonb(payload)))
            ident=cur.fetchone()[0]
    _recent[key]=now
    return {"accepted":True,"reference":f"CC-{ident:06d}"}
@app.get("/api/admin/inquiries")
def admin(request:Request):
    auth=request.headers.get("authorization","")
    if not secrets.compare_digest(auth,"Bearer "+ADMIN_TOKEN): raise HTTPException(401,"Unauthorized")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,kind,payload,status,created_at FROM public.catering_inquiries ORDER BY created_at DESC LIMIT 250")
            rows=cur.fetchall()
    return [{"id":r[0],"kind":r[1],"payload":r[2],"status":r[3],"created_at":r[4].isoformat()} for r in rows]
