import os, json, time, secrets, hashlib, hmac, base64, re
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
    customer=None
    if request.headers.get('authorization','').startswith('Bearer '):
        try: customer=account_id(request)
        except HTTPException: raise HTTPException(401,'Please sign in again')
    ip=request.client.host if request.client else "unknown"
    now=time.time()
    key=ip+":"+email.lower()
    if now-_recent.get(key,0)<5: raise HTTPException(429,"Please wait before submitting again")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO public.catering_inquiries(kind,payload,customer_id) VALUES (%s,%s,%s) RETURNING id",(data.kind,Jsonb(payload),customer))
            ident=cur.fetchone()[0]
    _recent[key]=now
    return {"accepted":True,"reference":f"CC-{ident:06d}"}
@app.get("/api/admin/inquiries")
def admin(request:Request):
    auth=request.headers.get("authorization","")
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,kind,payload,status,created_at FROM public.catering_inquiries ORDER BY created_at DESC LIMIT 250")
            rows=cur.fetchall()
    return [{"id":r[0],"kind":r[1],"payload":r[2],"status":r[3],"created_at":r[4].isoformat()} for r in rows]

# Customer portal: salted password hashes and expiring signed sessions.
class Account(BaseModel):
    email: str
    password: str
    name: str = ""
class Message(BaseModel):
    body: str
    inquiry_id: int | None = None
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return base64.urlsafe_b64encode(salt).decode()+"."+base64.urlsafe_b64encode(digest).decode()
def check_password(password, stored):
    try:
        salt, digest = stored.split(".")
        actual = hash_password(password, base64.urlsafe_b64decode(salt)).split(".")[1]
        return secrets.compare_digest(actual,digest)
    except Exception: return False
def make_session(customer_id):
    data = str(customer_id)+":"+str(int(time.time()+86400*7))
    signature = hmac.new(ADMIN_TOKEN.encode(),data.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode((data+":"+signature).encode()).decode()
def account_id(request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    try:
        decoded=base64.urlsafe_b64decode(token.encode()).decode()
        ident,expiry,signature=decoded.split(":")
        data=ident+":"+expiry
        valid=hmac.new(ADMIN_TOKEN.encode(),data.encode(),hashlib.sha256).hexdigest()
        if int(expiry)<time.time() or not secrets.compare_digest(signature,valid): raise ValueError()
        return int(ident)
    except Exception: raise HTTPException(401,"Sign in required")
@app.post("/api/customer/register",status_code=201)
def register(a:Account):
    email=a.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email) or len(email)>254: raise HTTPException(422,"Valid email required")
    if len(a.password)<12 or len(a.password)>128: raise HTTPException(422,"Password must be 12-128 characters")
    if not a.name.strip() or len(a.name)>120: raise HTTPException(422,"Name required")
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO public.catering_customers(email,password_hash,display_name) VALUES (%s,%s,%s) RETURNING id",(email,hash_password(a.password),a.name.strip()))
                ident=cur.fetchone()[0]
        return {"token":make_session(ident),"name":a.name.strip()}
    except psycopg.errors.UniqueViolation: raise HTTPException(409,"Account already exists; sign in")
@app.post("/api/customer/login")
def login(a:Account):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,password_hash,display_name FROM public.catering_customers WHERE email=%s",(a.email.strip().lower(),))
            row=cur.fetchone()
    if not row or not check_password(a.password,row[1]): raise HTTPException(401,"Incorrect email or password")
    return {"token":make_session(row[0]),"name":row[2]}
@app.get("/api/customer/dashboard")
def dashboard(request:Request):
    ident=account_id(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,kind,payload,status,created_at FROM public.catering_inquiries WHERE customer_id=%s ORDER BY id DESC LIMIT 100",(ident,))
            inquiries=[{"id":r[0],"kind":r[1],"payload":r[2],"status":r[3],"created_at":r[4].isoformat()} for r in cur.fetchall()]
            cur.execute("SELECT id,inquiry_id,sender,body,created_at FROM public.catering_messages WHERE customer_id=%s ORDER BY id ASC LIMIT 250",(ident,))
            messages=[{"id":r[0],"inquiry_id":r[1],"sender":r[2],"body":r[3],"created_at":r[4].isoformat()} for r in cur.fetchall()]
    return {"inquiries":inquiries,"messages":messages}
@app.post("/api/customer/messages",status_code=201)
def customer_message(m:Message,request:Request):
    ident=account_id(request)
    if not m.body.strip() or len(m.body)>3000: raise HTTPException(422,"Message must be 1-3000 characters")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            if m.inquiry_id:
                cur.execute("SELECT 1 FROM public.catering_inquiries WHERE id=%s AND customer_id=%s",(m.inquiry_id,ident))
                if not cur.fetchone(): raise HTTPException(403,"Event not found")
            cur.execute("INSERT INTO public.catering_messages(customer_id,inquiry_id,sender,body) VALUES (%s,%s,'customer',%s) RETURNING id",(ident,m.inquiry_id,m.body.strip()))
            mid=cur.fetchone()[0]
    return {"saved":True,"id":mid}
@app.post("/api/admin/messages",status_code=201)
def team_message(m:Message,request:Request,customer_id:int):
    admin_auth(request)
    if not m.body.strip() or len(m.body)>3000: raise HTTPException(422,"Invalid message")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO public.catering_messages(customer_id,inquiry_id,sender,body) VALUES (%s,%s,'team',%s) RETURNING id",(customer_id,m.inquiry_id,m.body.strip()))
            mid=cur.fetchone()[0]
    return {"saved":True,"id":mid}

class ChatQuestion(BaseModel):
    message: str = Field(min_length=1,max_length=900)
@app.post("/api/concierge")
def concierge(q:ChatQuestion):
    question=q.message.strip()
    lower=question.lower()
    # When a server-side API key is configured, use the model with strict business boundaries.
    key=os.environ.get("OPENAI_API_KEY","")
    if key:
        try:
            import urllib.request
            instructions=("You are the Culinary Creations Catering AI Event Coordinator and customer-service manager, representing a licensed and insured Delaware catering business. "
              "Take initiative to guide each visitor through a useful event consultation: ask one question at a time, including event type, date, location, guest count, desired service, dietary needs and budget. "
              "Explain menu options, recommend packages, calculate transparent preliminary per-guest estimates when enough details exist, and suggest the next step. "
              "Help wedding planners, venues and resellers understand the private partner application process, without disclosing wholesale prices. "
              "When a visitor wants a proposal, direct them to the Event Proposal form and explain that the submitted request goes to the catering management inbox. "
              "Be responsive, professional, and concise; never claim that you submitted a form, sent an email, booked a date, issued a quote, processed a payment, or contacted staff unless a verified system action actually happened. "
              "Do not request credit-card information or passwords. Do not promise availability, approve wholesale accounts or discounts, sign contracts, or confirm bookings. "
              "Escalate urgent issues or complaints to info@culinarycreationsgroup.com. "
              "Published per-person price tiers: Cold catering $14.95/$17.95/$21.95; Backyard BBQ $16.95/$22.95/$29.95; "
              "traditional buffets $18.95/$23.95/$28.95; wedding $34.95/$41.95/$47.50; breakfast $10.95/$14.95/$18.95; "
              "charcuterie $8.95/$10.95. Full-service catering adds a 22% service charge; standard staffing and equipment are included, bartending is separately quoted. "
              "No brisket is offered. Never disclose internal staffing costs. All proposals, prices and availability require team confirmation. "
              "Conclude with the most helpful specific question or action, rather than generic sales language.")
            body=json.dumps({"model":os.environ.get("OPENAI_MODEL","gpt-4.1-mini"),"instructions":instructions,"input":question,"max_output_tokens":250}).encode()
            req=urllib.request.Request("https://api.openai.com/v1/responses",data=body,headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},method="POST")
            with urllib.request.urlopen(req,timeout=12) as resp: result=json.load(resp)
            output=" ".join(part.get("text","") for item in result.get("output",[]) for part in item.get("content",[]) if part.get("type")=="output_text")
            if output.strip(): return {"reply":output.strip(),"mode":"ai"}
        except Exception: pass
    if any(w in lower for w in ["wholesale","partner","venue","planner","resell"]):
        reply="We welcome wedding planners, venues, caterers and event professionals! Select Partner With Us to apply for a customized partnership. All wholesale rates are privately quoted."
    elif any(w in lower for w in ["wedding","marriage","bride","groom"]):
        reply="Our wedding packages start at $34.95, $41.95 and $47.50 per guest, plus a 22% full-service charge. Standard event staffing and equipment are included. Choose Event Proposal to plan your celebration."
    elif any(w in lower for w in ["buffet","dinner","lunch"]):
        reply="Our traditional buffets start at $18.95, $23.95 and $28.95 per guest. You can add menu selections in Full Menu, then create an Event Proposal."
    elif any(w in lower for w in ["bbq","barbecue","cookout"]):
        reply="Our BBQ packages start at $16.95, $22.95 and $29.95 per guest. Browse Full Menu and add your selections to an Event Proposal."
    elif any(w in lower for w in ["breakfast","brunch"]):
        reply="Breakfast packages start at $10.95, $14.95 and $18.95 per guest. We can customize your menu through the Event Proposal form."
    elif any(w in lower for w in ["staff","server","service fee","22%"]):
        reply="Standard staffing and food-service equipment are included with our full-service packages. A 22% service charge applies to full-service catering; bartending is quoted separately."
    elif any(w in lower for w in ["book","available","date","reserve","deposit","payment"]):
        reply="Our team must confirm availability, final pricing and booking details. Please complete Event Proposal with your date, location and guest count, or email info@culinarycreationsgroup.com."
    else:
        reply="I'd be happy to help! We cater weddings, corporate events, private parties, BBQs, buffets and more throughout Delaware. Choose Full Menu to explore options, Event Proposal to request catering, or Partner With Us for wholesale inquiries. You can also email info@culinarycreationsgroup.com."
    return {"reply":reply,"mode":"guided"}

# Management accounts use the same salted password hashes as customer accounts.
# The existing ADMIN_TOKEN remains server-side as the session signing secret.
OWNER_EMAIL=os.environ.get("OWNER_EMAIL","info@culinarycreationsgroup.com").strip().lower()
def admin_id(request):
    token=request.headers.get("authorization","").removeprefix("Bearer ").strip()
    try:
        raw=base64.urlsafe_b64decode(token.encode()).decode()
        prefix,ident,expiry,signature=raw.split(":")
        message="admin:"+ident+":"+expiry
        expected=hmac.new(ADMIN_TOKEN.encode(),message.encode(),hashlib.sha256).hexdigest()
        if prefix!="admin" or int(expiry)<time.time() or not secrets.compare_digest(signature,expected): raise ValueError()
        return int(ident)
    except Exception: raise HTTPException(401,"Management sign-in required")
def admin_auth(request):
    admin_id(request)
@app.post("/api/admin/login")
def admin_login(a:Account):
    email=a.email.strip().lower()
    configured_email=os.environ.get("OWNER_EMAIL","info@culinarycreationsgroup.com").strip().lower()
    password_hash=os.environ.get("OWNER_PASSWORD_HASH","")
    if email!=configured_email or not password_hash or not check_password(a.password,password_hash):
        raise HTTPException(401,"Incorrect email or password")
    data="admin:1:"+str(int(time.time()+86400))
    signature=hmac.new(ADMIN_TOKEN.encode(),data.encode(),hashlib.sha256).hexdigest()
    return {"token":base64.urlsafe_b64encode((data+":"+signature).encode()).decode(),"name":"Culinary Creations Management"}
class StatusUpdate(BaseModel):
    status: str
@app.get("/api/admin/conversations")
def admin_conversations(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT c.id,c.display_name,c.email,COUNT(m.id),MAX(m.created_at) FROM public.catering_customers c LEFT JOIN public.catering_messages m ON m.customer_id=c.id GROUP BY c.id,c.display_name,c.email ORDER BY MAX(m.created_at) DESC NULLS LAST LIMIT 250")
            people=[{"id":r[0],"name":r[1],"email":r[2],"messages":r[3],"last_message":r[4].isoformat() if r[4] else None} for r in cur.fetchall()]
            cur.execute("SELECT customer_id,inquiry_id,sender,body,created_at FROM public.catering_messages ORDER BY created_at ASC LIMIT 1000")
            messages=[{"customer_id":r[0],"inquiry_id":r[1],"sender":r[2],"body":r[3],"created_at":r[4].isoformat()} for r in cur.fetchall()]
    return {"customers":people,"messages":messages}
@app.patch("/api/admin/inquiries/{inquiry_id}")
def update_inquiry(inquiry_id:int,data:StatusUpdate,request:Request):
    admin_auth(request)
    if data.status not in ("new","reviewing","quoted","confirmed","completed","declined"): raise HTTPException(422,"Invalid status")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE public.catering_inquiries SET status=%s WHERE id=%s RETURNING id",(data.status,inquiry_id))
            if not cur.fetchone(): raise HTTPException(404,"Inquiry not found")
    return {"saved":True}
