import os, json, time, secrets, hashlib, hmac, base64, re
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import psycopg
from psycopg.types.json import Jsonb

app = FastAPI(title="Culinary Creations Inquiries", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["https://culinary-creations-catering.onrender.com","https://culinary-creations-product-demo.onrender.com"], allow_methods=["POST","GET","PUT","PATCH"], allow_headers=["Content-Type","Authorization"])
DATABASE_URL=os.environ["DATABASE_URL"]
ADMIN_TOKEN=os.environ["ADMIN_TOKEN"]
_recent={}
_rate_hits={}
@app.middleware("http")
async def security_headers(request:Request,call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Cache-Control"]="no-store" if request.url.path.startswith("/api/") else "public, max-age=60"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    return response

def throttle(request,group,limit,window=300):
    # In-process limit is a temporary defense; distributed rate limiting is needed across instances.
    now=time.time()
    identity=(request.client.host if request.client else "unknown")
    key=(group,identity)
    hits=[t for t in _rate_hits.get(key,[]) if now-t<window]
    if len(hits)>=limit: raise HTTPException(429,"Too many attempts. Please try again later.")
    hits.append(now)
    _rate_hits[key]=hits

class Inquiry(BaseModel):
    kind: str
    payload: dict
    website: str = ""

# Delivery quotes use server-side Google Routes API; never expose the key to browsers.
class DeliveryRoute(BaseModel):
    destination: str = Field(min_length=8,max_length=250)

@app.post("/api/delivery/quote")
def delivery_quote(data:DeliveryRoute, request:Request):
    throttle(request,"delivery-route",12,300)
    key=os.environ.get("GOOGLE_MAPS_API_KEY","")
    if not key: raise HTTPException(503,"Automatic road mileage is temporarily unavailable")
    import urllib.request, urllib.error
    payload={"origin":{"address":"1036 Lafferty Lane, Dover, DE 19901"},"destination":{"address":data.destination.strip()},"travelMode":"DRIVE","routingPreference":"TRAFFIC_UNAWARE","units":"IMPERIAL"}
    req=urllib.request.Request("https://routes.googleapis.com/directions/v2:computeRoutes",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json","X-Goog-Api-Key":key,"X-Goog-FieldMask":"routes.distanceMeters"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=12) as resp:
            result=json.load(resp)
        meters=result["routes"][0]["distanceMeters"]
    except (urllib.error.URLError,KeyError,IndexError,ValueError,TimeoutError):
        raise HTTPException(422,"Unable to calculate driving distance. Please check the event address.")
    miles=round(meters/1609.344,1)
    charge=20 if miles<=15 else 30 if miles<=30 else 45 if miles<=50 else None
    return {"origin":"1036 Lafferty Lane, Dover, DE 19901","destination":data.destination.strip(),"one_way_miles":miles,"delivery_fee":charge,"custom_quote":charge is None,"currency":"USD"}

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
            # Every inquiry belongs to a CRM customer record. Unverified email
            # submissions never grant access to an existing customer's portal.
            cur.execute("SELECT id FROM public.catering_customers WHERE email=%s",(email.lower(),))
            existing=cur.fetchone()
            if existing:
                if customer is not None and customer!=existing[0]:
                    raise HTTPException(403,"Signed-in account does not match inquiry email")
                # Do not associate an unauthenticated inquiry with a preexisting
                # account: an attacker must not inject requests into its portal.
                if customer is not None: customer=existing[0]
            else:
                if customer is not None:
                    raise HTTPException(403,"Please use the email on your account")
                display=str(payload.get("client") or payload.get("contact") or payload.get("business") or "Customer")[:120]
                random_password=secrets.token_urlsafe(48)
                cur.execute("INSERT INTO public.catering_customers(email,password_hash,display_name) VALUES (%s,%s,%s) RETURNING id",(email.lower(),hash_password(random_password),display))
                customer=cur.fetchone()[0]
            cur.execute("INSERT INTO public.catering_inquiries(kind,payload,customer_id) VALUES (%s,%s,%s) RETURNING id",(data.kind,Jsonb({**payload,"_management":lead_review(data.kind,payload)}),customer))
            ident=cur.fetchone()[0]
    _recent[key]=now
    return {"accepted":True,"reference":f"CC-{ident:06d}"}
def lead_review(kind,payload):
    """Deterministic, auditable lead triage; no fabricated bookings or AI claims."""
    fields=["date","guests","venue","eventtype","service"] if kind=="event" else ["phone","details"]
    missing=[f for f in fields if not str(payload.get(f,"")).strip()]
    guest_text=str(payload.get("guests","")).strip()
    try: guests=int(guest_text)
    except (ValueError,TypeError): guests=0
    priority="high" if kind=="event" and guests>=100 else "normal"
    next_step=("Request missing "+", ".join(missing) if missing else
               "Review event requirements and prepare a proposal" if kind=="event" else
               "Review partner eligibility and contact applicant")
    return {"priority":priority,"missing":missing,"next_step":next_step,"reviewed_by":"automated intake","requires_staff_approval":True}
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
    otp: str = ""
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
class ActivateAccount(BaseModel):
    email: str
    password: str
    token: str

@app.post("/api/customer/activate")
def activate_account(a:ActivateAccount,request:Request):
    throttle(request,"activate",6,900)
    if len(a.password)<12 or len(a.password)>128: raise HTTPException(422,"Password must be 12-128 characters")
    if not re.fullmatch(r"[A-Za-z0-9_-]{30,150}",a.token): raise HTTPException(400,"Invalid activation token")
    digest=hashlib.sha256(a.token.encode()).hexdigest()
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS public.catering_activations (customer_id BIGINT PRIMARY KEY REFERENCES public.catering_customers(id) ON DELETE CASCADE, token_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)")
            cur.execute("SELECT c.id FROM public.catering_customers c JOIN public.catering_activations a ON a.customer_id=c.id WHERE c.email=%s AND a.token_hash=%s AND a.expires_at>NOW() FOR UPDATE OF a",(a.email.strip().lower(),digest))
            row=cur.fetchone()
            if not row: raise HTTPException(400,"Activation link invalid or expired")
            cur.execute("UPDATE public.catering_customers SET password_hash=%s WHERE id=%s",(hash_password(a.password),row[0]))
            cur.execute("DELETE FROM public.catering_activations WHERE customer_id=%s",(row[0],))
    return {"token":make_session(row[0]),"activated":True}

@app.post("/api/customer/register",status_code=201)
def register(a:Account,request:Request):
    throttle(request,"register",8,3600)
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
def login(a:Account,request:Request):
    throttle(request,"customer_login",10,300)
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
            cur.execute("SELECT 1 FROM public.catering_customers WHERE id=%s",(customer_id,))
            if not cur.fetchone(): raise HTTPException(404,"Customer not found")
            if m.inquiry_id:
                cur.execute("SELECT 1 FROM public.catering_inquiries WHERE id=%s AND customer_id=%s",(m.inquiry_id,customer_id))
                if not cur.fetchone(): raise HTTPException(403,"Inquiry does not belong to this customer")
            cur.execute("INSERT INTO public.catering_messages(customer_id,inquiry_id,sender,body) VALUES (%s,%s,'team',%s) RETURNING id",(customer_id,m.inquiry_id,m.body.strip()))
            mid=cur.fetchone()[0]
    return {"saved":True,"id":mid}

class ChatQuestion(BaseModel):
    message: str = Field(min_length=1,max_length=900)
    name: str = Field(default="",max_length=100)
    history: list[dict] = Field(default_factory=list,max_length=16)
    page: str = Field(default="",max_length=80)
@app.post("/api/concierge")
def concierge(q:ChatQuestion,request:Request):
    throttle(request,"concierge",35,300)
    question=q.message.strip()
    lower=question.lower()
    visitor=q.name.strip().split(" ")[0] if q.name.strip() else ""
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
              "Remember the visitor name and details supplied in recent_conversation, use their first name naturally but not in every sentence. Respond to their latest question in context. "
              "Offer one specific next step and one relevant follow-up question. Never ask for details they already provided. "
              "When on a menu page, help select dishes; when discussing a proposal, help complete it; when on the partner section, explain partner enrollment. "
              "Do not claim that browsing pages or chatting alone submits a lead. Ask consent before collecting contact details and direct visitors to the proposal form. "
              "Conclude with the most helpful specific question or action, rather than generic sales language.")
            body=json.dumps({"model":os.environ.get("OPENAI_MODEL","gpt-4.1-mini"),"instructions":instructions,"input":json.dumps({"visitor_name":visitor,"current_page":q.page,"recent_conversation":q.history[-12:],"latest_message":question}),"max_output_tokens":350}).encode()
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
    if visitor: reply=visitor+", "+reply[0].lower()+reply[1:]
    if False and "260" in question and ("wedding" in lower or any("wedding" in str(x).lower() for x in q.history)):
        reply=f"{visitor + ', ' if visitor else ''}for 260 wedding guests, our three published package bases are $9,087, $10,907 and $12,350. With the 22% full-service charge, preliminary totals are $11,086.14, $13,306.54 and $15,067, before any separately quoted services. What is your wedding date?"
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
def verify_owner_totp(code,secret):
    try:
        normalized=secret.replace(" ","").upper()
        key=base64.b32decode(normalized+"="*((-len(normalized))%8))
        if not re.fullmatch(r"\d{6}",code or ""): return False
        counter=int(time.time()//30)
        for drift in (-1,0,1):
            digest=hmac.new(key,(counter+drift).to_bytes(8,"big"),hashlib.sha1).digest()
            offset=digest[-1]&15
            value=(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000
            if secrets.compare_digest(str(value).zfill(6),code): return True
    except Exception: pass
    return False
@app.post("/api/admin/login")
def admin_login(a:Account,request:Request):
    throttle(request,"admin_login",6,900)
    email=a.email.strip().lower()
    configured_email=os.environ.get("OWNER_EMAIL","info@culinarycreationsgroup.com").strip().lower()
    password_hash=os.environ.get("OWNER_PASSWORD_HASH","")
    if email!=configured_email or not password_hash or not check_password(a.password,password_hash):
        raise HTTPException(401,"Incorrect email or password")
    otp_secret=os.environ.get("OWNER_TOTP_SECRET","").strip()
    if otp_secret and not verify_owner_totp(a.otp,otp_secret): raise HTTPException(401,"Valid authenticator code required")
    data="admin:1:"+str(int(time.time()+8*3600))
    signature=hmac.new(ADMIN_TOKEN.encode(),data.encode(),hashlib.sha256).hexdigest()
    return {"token":base64.urlsafe_b64encode((data+":"+signature).encode()).decode(),"name":"Culinary Creations Management"}
class StatusUpdate(BaseModel):
    status: str
@app.get("/api/admin/worklist")
def admin_worklist(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,kind,payload,status,created_at FROM public.catering_inquiries WHERE status NOT IN ('completed','declined') ORDER BY created_at DESC LIMIT 250")
            rows=cur.fetchall()
    tasks=[]
    for ident,kind,payload,status,created in rows:
        review=lead_review(kind,payload)
        tasks.append({"id":ident,"kind":kind,"status":status,"customer":payload.get("client") or payload.get("business") or "Customer","email":payload.get("email",""),"priority":review["priority"],"next_step":review["next_step"],"age_days":max(0,(datetime.now(timezone.utc)-created.replace(tzinfo=timezone.utc) if created.tzinfo is None else datetime.now(timezone.utc)-created).days)})
    return {"tasks":tasks,"open":len(tasks),"needs_followup":sum(t["age_days"]>=2 and t["status"] in ("new","reviewing") for t in tasks)}
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

# Catering CRM: client projects and owner-controlled partner eligibility.
class ProjectRequest(BaseModel):
    title: str = Field(min_length=3,max_length=160)
    event_date: str = Field(default="",max_length=40)
    location: str = Field(default="",max_length=250)
    guests: int | None = Field(default=None,ge=1,le=100000)
    notes: str = Field(default="",max_length=4000)
    kind: str = Field(default="event")
class PartnerDecision(BaseModel):
    tier: str = "pending"
    notes: str = Field(default="",max_length=2000)
def ensure_crm(cur):
    cur.execute("""CREATE TABLE IF NOT EXISTS public.catering_crm_projects (
        id BIGSERIAL PRIMARY KEY,
        customer_id BIGINT NOT NULL REFERENCES public.catering_customers(id) ON DELETE CASCADE,
        title TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'event',
        event_date TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '',
        guests INTEGER, notes TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'requested',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS public.catering_partner_accounts (
        customer_id BIGINT PRIMARY KEY REFERENCES public.catering_customers(id) ON DELETE CASCADE,
        tier TEXT NOT NULL DEFAULT 'pending', notes TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
@app.post("/api/customer/projects",status_code=201)
def create_project(data:ProjectRequest,request:Request):
    ident=account_id(request)
    throttle(request,"projects",20,3600)
    if data.kind not in ("event","recurring","wholesale_bid"): raise HTTPException(422,"Invalid project type")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_crm(cur)
            cur.execute("INSERT INTO public.catering_crm_projects(customer_id,title,kind,event_date,location,guests,notes) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",(ident,data.title.strip(),data.kind,data.event_date.strip(),data.location.strip(),data.guests,data.notes.strip()))
            ident_project=cur.fetchone()[0]
    return {"id":ident_project,"status":"requested"}
@app.get("/api/customer/projects")
def customer_projects(request:Request):
    ident=account_id(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_crm(cur)
            cur.execute("SELECT id,title,kind,event_date,location,guests,notes,status,created_at FROM public.catering_crm_projects WHERE customer_id=%s ORDER BY id DESC",(ident,))
            projects=[{"id":r[0],"title":r[1],"kind":r[2],"event_date":r[3],"location":r[4],"guests":r[5],"notes":r[6],"status":r[7],"created_at":r[8].isoformat()} for r in cur.fetchall()]
            cur.execute("SELECT tier FROM public.catering_partner_accounts WHERE customer_id=%s",(ident,))
            partner=cur.fetchone()
    return {"projects":projects,"partner_tier":partner[0] if partner else "not_approved"}
@app.get("/api/admin/crm")
def admin_crm(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_crm(cur)
            cur.execute("""SELECT c.id,c.display_name,c.email,COALESCE(p.tier,'not_approved')
                FROM public.catering_customers c LEFT JOIN public.catering_partner_accounts p ON p.customer_id=c.id
                ORDER BY c.id DESC LIMIT 300""")
            clients=[{"id":r[0],"name":r[1],"email":r[2],"tier":r[3]} for r in cur.fetchall()]
            cur.execute("""SELECT p.id,p.customer_id,c.display_name,p.title,p.kind,p.event_date,p.status
                FROM public.catering_crm_projects p JOIN public.catering_customers c ON c.id=p.customer_id
                ORDER BY p.id DESC LIMIT 300""")
            projects=[{"id":r[0],"customer_id":r[1],"client":r[2],"title":r[3],"kind":r[4],"event_date":r[5],"status":r[6]} for r in cur.fetchall()]
    return {"clients":clients,"projects":projects}
@app.put("/api/admin/partners/{customer_id}")
def set_partner_tier(customer_id:int,data:PartnerDecision,request:Request):
    admin_auth(request)
    if data.tier not in ("pending","catering_20","reseller_30","reseller_35","white_label_40","white_label_50","declined"):
        raise HTTPException(422,"Invalid tier")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_crm(cur)
            cur.execute("SELECT 1 FROM public.catering_customers WHERE id=%s",(customer_id,))
            if not cur.fetchone(): raise HTTPException(404,"Customer not found")
            cur.execute("""INSERT INTO public.catering_partner_accounts(customer_id,tier,notes)
                VALUES (%s,%s,%s) ON CONFLICT(customer_id) DO UPDATE
                SET tier=EXCLUDED.tier,notes=EXCLUDED.notes,updated_at=NOW()""",(customer_id,data.tier,data.notes))
    return {"saved":True,"customer_id":customer_id,"tier":data.tier}
class ProjectStatus(BaseModel):
    status: str
@app.patch("/api/admin/projects/{project_id}")
def admin_project_status(project_id:int,data:ProjectStatus,request:Request):
    admin_auth(request)
    if data.status not in ("requested","reviewing","quoted","approved","scheduled","completed","cancelled"):
        raise HTTPException(422,"Invalid project status")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_crm(cur)
            cur.execute("UPDATE public.catering_crm_projects SET status=%s WHERE id=%s RETURNING id",(data.status,project_id))
            if not cur.fetchone(): raise HTTPException(404,"Project not found")
    return {"saved":True}

# Project workspace: non-billing CRM documents, tasks, questionnaires, appointments.
# Draft contracts and acknowledgements are not legally verified e-signatures.
WORKSPACE_TYPES={"proposal","contract","questionnaire","task","appointment","note","document"}
class WorkspaceItem(BaseModel):
    project_id: int
    item_type: str
    title: str = Field(min_length=2,max_length=180)
    content: str = Field(default="",max_length=12000)
    due_date: str = Field(default="",max_length=40)
    status: str = "draft"
class WorkspaceChange(BaseModel):
    status: str
def ensure_workspace(cur):
    ensure_crm(cur)
    cur.execute("""CREATE TABLE IF NOT EXISTS public.catering_workspace_items (
      id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES public.catering_crm_projects(id) ON DELETE CASCADE,
      item_type TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL DEFAULT '',
      due_date TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS public.catering_workspace_activity (
      id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES public.catering_crm_projects(id) ON DELETE CASCADE,
      actor TEXT NOT NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
def workspace_rows(cur,where,args):
    cur.execute("SELECT w.id,w.project_id,w.item_type,w.title,w.content,w.due_date,w.status,w.created_at FROM public.catering_workspace_items w WHERE "+where+" ORDER BY w.id DESC LIMIT 500",args)
    return [{"id":r[0],"project_id":r[1],"type":r[2],"title":r[3],"content":r[4],"due_date":r[5],"status":r[6],"created_at":r[7].isoformat()} for r in cur.fetchall()]
@app.get("/api/customer/workspace")
def customer_workspace(request:Request):
    ident=account_id(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_workspace(cur)
            return {"items":workspace_rows(cur,"w.project_id IN (SELECT id FROM public.catering_crm_projects WHERE customer_id=%s) AND w.status NOT IN ('draft','internal')",(ident,))}
@app.get("/api/admin/workspace")
def admin_workspace(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_workspace(cur)
            return {"items":workspace_rows(cur,"TRUE",())}
@app.post("/api/admin/workspace",status_code=201)
def create_workspace_item(data:WorkspaceItem,request:Request):
    admin_auth(request)
    if data.item_type not in WORKSPACE_TYPES or data.status not in ("draft","shared","internal","completed","cancelled"):
        raise HTTPException(422,"Invalid item type or status")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_workspace(cur)
            cur.execute("SELECT 1 FROM public.catering_crm_projects WHERE id=%s",(data.project_id,))
            if not cur.fetchone(): raise HTTPException(404,"Project not found")
            cur.execute("""INSERT INTO public.catering_workspace_items(project_id,item_type,title,content,due_date,status)
              VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",(data.project_id,data.item_type,data.title.strip(),data.content,data.due_date,data.status))
            ident=cur.fetchone()[0]
            cur.execute("INSERT INTO public.catering_workspace_activity(project_id,actor,action) VALUES (%s,'team',%s)",(data.project_id,"Created "+data.item_type+" #"+str(ident)))
    return {"id":ident,"saved":True}
@app.patch("/api/admin/workspace/{item_id}")
def update_workspace_item(item_id:int,data:WorkspaceChange,request:Request):
    admin_auth(request)
    if data.status not in ("draft","shared","internal","completed","cancelled"):
        raise HTTPException(422,"Invalid status")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_workspace(cur)
            cur.execute("UPDATE public.catering_workspace_items SET status=%s,updated_at=NOW() WHERE id=%s RETURNING project_id",(data.status,item_id))
            row=cur.fetchone()
            if not row: raise HTTPException(404,"Item not found")
            cur.execute("INSERT INTO public.catering_workspace_activity(project_id,actor,action) VALUES (%s,'team',%s)",(row[0],"Changed workspace item #"+str(item_id)+" to "+data.status))
    return {"saved":True}
@app.get("/api/admin/activity")
def workspace_activity(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            ensure_workspace(cur)
            cur.execute("SELECT a.project_id,a.actor,a.action,a.created_at FROM public.catering_workspace_activity a ORDER BY a.id DESC LIMIT 100")
            rows=cur.fetchall()
    return {"activity":[{"project_id":r[0],"actor":r[1],"action":r[2],"date":r[3].isoformat()} for r in rows]}

# Isolated shared demo backend. Each visitor receives an opaque demo session token.
# Demo state never queries or modifies live catering customer/partner tables.
class DemoState(BaseModel):
    state: dict
def demo_schema(cur):
    cur.execute("""CREATE TABLE IF NOT EXISTS public.catering_demo_sessions (
      session_hash TEXT PRIMARY KEY, state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
def demo_ident(request):
    token=request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,100}",token):
        raise HTTPException(401,"Demo session required")
    return hashlib.sha256(token.encode()).hexdigest()
@app.post("/api/demo/session")
def demo_session(request:Request):
    throttle(request,"demo-session",30,300)
    token=secrets.token_urlsafe(48)
    return {"demo_token":token,"mode":"sandbox","production_access":False}
@app.get("/api/demo/state")
def demo_get(request:Request):
    sid=demo_ident(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            demo_schema(cur)
            cur.execute("SELECT state FROM public.catering_demo_sessions WHERE session_hash=%s",(sid,))
            row=cur.fetchone()
    return {"state":row[0] if row else None,"mode":"sandbox"}
@app.put("/api/demo/state")
def demo_put(data:DemoState,request:Request):
    sid=demo_ident(request)
    raw=json.dumps(data.state)
    if len(raw)>100000: raise HTTPException(413,"Demo state too large")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            demo_schema(cur)
            cur.execute("""INSERT INTO public.catering_demo_sessions(session_hash,state)
            VALUES (%s,%s) ON CONFLICT (session_hash) DO UPDATE SET
            state=EXCLUDED.state,updated_at=NOW()""",(sid,Jsonb(data.state)))
    return {"saved":True,"mode":"sandbox"}

# TMJames Group owns the platform; Culinary Creations is the fulfillment business.
# Production reseller API: separate tenant rows, owner-issued invitations and scoped access.
def reseller_schema(cur):
    cur.execute("""CREATE TABLE IF NOT EXISTS public.cc_reseller_tenants(
      id BIGSERIAL PRIMARY KEY, business_name TEXT NOT NULL,
      contact_email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'approved',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS public.cc_reseller_access(
      tenant_id BIGINT NOT NULL REFERENCES public.cc_reseller_tenants(id),
      token_hash TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    cur.execute("""CREATE TABLE IF NOT EXISTS public.cc_reseller_records(
      id BIGSERIAL PRIMARY KEY, tenant_id BIGINT NOT NULL REFERENCES public.cc_reseller_tenants(id),
      record_type TEXT NOT NULL, payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
class ResellerInvite(BaseModel):
    business_name: str = Field(min_length=2,max_length=160)
    contact_email: str = Field(min_length=5,max_length=254)
class ResellerRecord(BaseModel):
    record_type: str
    payload: dict
def reseller_identity(request):
    token=request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,100}",token):
        raise HTTPException(401,"Reseller sign-in required")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("""SELECT a.tenant_id FROM public.cc_reseller_access a
              JOIN public.cc_reseller_tenants t ON t.id=a.tenant_id
              WHERE a.token_hash=%s AND a.expires_at>NOW() AND t.status='approved'""",
              (hashlib.sha256(token.encode()).hexdigest(),))
            row=cur.fetchone()
    if not row: raise HTTPException(401,"Reseller access expired or revoked")
    return row[0]
@app.post("/api/admin/resellers")
def create_reseller(data:ResellerInvite,request:Request):
    admin_auth(request)
    token=secrets.token_urlsafe(48)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("""INSERT INTO public.cc_reseller_tenants(business_name,contact_email)
               VALUES(%s,%s) RETURNING id""",(data.business_name.strip(),data.contact_email.strip().lower()))
            tenant_id=cur.fetchone()[0]
            cur.execute("""INSERT INTO public.cc_reseller_access(tenant_id,token_hash,expires_at)
               VALUES(%s,%s,NOW()+INTERVAL '30 days')""",
               (tenant_id,hashlib.sha256(token.encode()).hexdigest()))
    return {"tenant_id":tenant_id,"business_name":data.business_name,"invitation_token":token,
            "warning":"Show this token once. Use secure invitation delivery. This is a temporary access mechanism, not a full login."}
@app.get("/api/admin/resellers")
def list_resellers(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("ALTER TABLE public.cc_reseller_tenants ADD COLUMN IF NOT EXISTS pricing_tier TEXT")
            cur.execute("SELECT id,business_name,contact_email,status,pricing_tier FROM public.cc_reseller_tenants ORDER BY id DESC")
            rows=cur.fetchall()
    return {"owner":"TMJames Group","fulfillment":"Culinary Creations Catering",
            "resellers":[{"id":r[0],"business_name":r[1],"contact_email":r[2],"status":r[3],"pricing_tier":r[4]} for r in rows]}
@app.get("/api/reseller/me")
def reseller_me(request:Request):
    tenant_id=reseller_identity(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT business_name,contact_email FROM public.cc_reseller_tenants WHERE id=%s",(tenant_id,))
            row=cur.fetchone()
    return {"tenant_id":tenant_id,"business_name":row[0],"contact_email":row[1],
            "platform_owner":"TMJames Group","supplier":"Culinary Creations Catering"}
@app.get("/api/reseller/records")
def reseller_records(request:Request,record_type:str=""):
    tenant_id=reseller_identity(request)
    valid={"menu","customer","event","quote","message","task","supplier_request"}
    if record_type and record_type not in valid: raise HTTPException(400,"Unsupported record type")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            if record_type:
                cur.execute("SELECT id,record_type,payload FROM public.cc_reseller_records WHERE tenant_id=%s AND record_type=%s ORDER BY id DESC LIMIT 500",(tenant_id,record_type))
            else:
                cur.execute("SELECT id,record_type,payload FROM public.cc_reseller_records WHERE tenant_id=%s ORDER BY id DESC LIMIT 500",(tenant_id,))
            rows=cur.fetchall()
    return {"records":[{"id":r[0],"record_type":r[1],"payload":r[2]} for r in rows]}
@app.post("/api/reseller/records")
def reseller_add_record(data:ResellerRecord,request:Request):
    tenant_id=reseller_identity(request)
    valid={"menu","customer","event","quote","message","task","supplier_request"}
    if data.record_type not in valid: raise HTTPException(400,"Unsupported record type")
    if len(json.dumps(data.payload))>20000: raise HTTPException(413,"Record too large")
    if data.record_type=="quote":
        import math
        lines=data.payload.get("lines")
        if not isinstance(lines,list) or not 1<=len(lines)<=100:
            raise HTTPException(400,"Quote must contain 1–100 items")
        try:
            customer_id=int(data.payload["customer_id"])
            menu_ids=[int(line["menu_id"]) for line in lines]
            quantities=[int(line["quantity"]) for line in lines]
            prices=[float(line["price"]) for line in lines]
        except (KeyError,TypeError,ValueError,OverflowError):
            raise HTTPException(400,"Invalid quote details")
        if any(q<1 or q>10000 for q in quantities) or any(not math.isfinite(p) or p<0 or p>1000000 for p in prices):
            raise HTTPException(400,"Invalid quote quantity or price")
        with psycopg.connect(DATABASE_URL) as verify_conn:
            with verify_conn.cursor() as cur:
                cur.execute("SELECT id FROM public.cc_reseller_records WHERE id=%s AND tenant_id=%s AND record_type='customer'",(customer_id,tenant_id))
                if not cur.fetchone(): raise HTTPException(400,"Customer does not belong to this reseller")
                cur.execute("SELECT id,payload FROM public.cc_reseller_records WHERE tenant_id=%s AND record_type='menu' AND id=ANY(%s)",(tenant_id,menu_ids))
                menus={row[0]:row[1] for row in cur.fetchall()}
        if len(menus)!=len(set(menu_ids)):
            raise HTTPException(400,"Quote contains an unauthorized menu item")
        validated=[]
        for line,menu_id,q,p in zip(lines,menu_ids,quantities,prices):
            m=menus[menu_id]
            validated.append({"menu_id":menu_id,"master_id":m["master_id"],"menu_name":m["alias"],"quantity":q,"price":p})
        data.payload={"customer_id":customer_id,"event":str(data.payload.get("event",""))[:300],
                      "lines":validated,"total":round(sum(x["quantity"]*x["price"] for x in validated),2),
                      "status":"draft","currency":"USD"}
    if data.record_type=="supplier_request":
        try:
            quote_id=int(data.payload["quote_id"])
        except (KeyError,TypeError,ValueError):
            raise HTTPException(400,"A saved quote is required")
        with psycopg.connect(DATABASE_URL) as verify_conn:
            with verify_conn.cursor() as verify_cur:
                verify_cur.execute("""SELECT payload FROM public.cc_reseller_records
                    WHERE id=%s AND tenant_id=%s AND record_type='quote'""",(quote_id,tenant_id))
                quote_row=verify_cur.fetchone()
                if not quote_row: raise HTTPException(404,"Quote not found for this reseller")
                verify_cur.execute("""SELECT id FROM public.cc_reseller_records
                    WHERE tenant_id=%s AND record_type='supplier_request'
                    AND payload->>'quote_id'=%s LIMIT 1""",(tenant_id,str(quote_id)))
                if verify_cur.fetchone(): raise HTTPException(409,"A supplier request already exists for this quote")
        quote_lines=quote_row[0].get("lines",[])
        if not isinstance(quote_lines,list) or not quote_lines:
            raise HTTPException(400,"Quote has no order lines")
        data.payload={"quote_id":quote_id,"lines":quote_lines,"status":"pending_review"}

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO public.cc_reseller_records(tenant_id,record_type,payload) VALUES(%s,%s,%s) RETURNING id",
                        (tenant_id,data.record_type,Jsonb(data.payload)))
            record_id=cur.fetchone()[0]
    return {"id":record_id,"tenant_id":tenant_id,"status":"saved","supplier_committed":False}

class FulfillmentDecision(BaseModel):
    status: str
    notes: str = Field(default="",max_length=1500)
@app.get("/api/admin/reseller-fulfillment")
def owner_fulfillment(request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("""SELECT r.id,r.tenant_id,t.business_name,r.payload,r.created_at
                FROM public.cc_reseller_records r JOIN public.cc_reseller_tenants t ON t.id=r.tenant_id
                WHERE r.record_type='supplier_request' ORDER BY r.id DESC LIMIT 300""")
            rows=cur.fetchall()
    return {"requests":[{"id":r[0],"tenant_id":r[1],"business_name":r[2],
        "payload":r[3],"created_at":r[4].isoformat()} for r in rows]}
@app.patch("/api/admin/reseller-fulfillment/{request_id}")
def owner_fulfillment_decision(request_id:int,data:FulfillmentDecision,request:Request):
    admin_auth(request)
    if data.status not in {"pending_review","approved","declined","scheduled","completed"}:
        raise HTTPException(400,"Unsupported fulfillment status")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("""SELECT payload FROM public.cc_reseller_records
                WHERE id=%s AND record_type='supplier_request' FOR UPDATE""",(request_id,))
            row=cur.fetchone()
            if not row: raise HTTPException(404,"Supplier request not found")
            current=row[0]
            old=current.get("status","pending_review")
            transitions={"pending_review":{"approved","declined"},
                "approved":{"scheduled","declined"},
                "scheduled":{"completed"},
                "declined":set(),"completed":set()}
            if data.status!=old and data.status not in transitions.get(old,set()):
                raise HTTPException(409,"Invalid fulfillment status transition")
            updated={**current,"status":data.status,"supplier_notes":data.notes,
                "reviewed_at":datetime.now(timezone.utc).isoformat()}
            cur.execute("""UPDATE public.cc_reseller_records SET payload=%s,updated_at=NOW()
                WHERE id=%s""",(Jsonb(updated),request_id))
    return {"id":request_id,"status":data.status}

# Partner food-only wholesale discounts; never accept tier or costs from reseller payloads.
WHOLESALE_TIERS={"catering_20":20,"reseller_30":30,"reseller_35":35,"white_label_40":40,"white_label_50":50}
class PartnerTierUpdate(BaseModel):
    tier: str
@app.patch("/api/admin/resellers/{tenant_id}/tier")
def assign_reseller_tier(tenant_id:int,data:PartnerTierUpdate,request:Request):
    admin_auth(request)
    if data.tier not in WHOLESALE_TIERS: raise HTTPException(400,"Unknown pricing tier")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("ALTER TABLE public.cc_reseller_tenants ADD COLUMN IF NOT EXISTS pricing_tier TEXT")
            cur.execute("UPDATE public.cc_reseller_tenants SET pricing_tier=%s WHERE id=%s RETURNING id",
                        (data.tier,tenant_id))
            if not cur.fetchone(): raise HTTPException(404,"Reseller not found")
    return {"tenant_id":tenant_id,"tier":data.tier,"discount_percent":WHOLESALE_TIERS[data.tier]}
@app.get("/api/reseller/wholesale-pricing")
def reseller_wholesale_pricing(request:Request):
    tenant_id=reseller_identity(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("ALTER TABLE public.cc_reseller_tenants ADD COLUMN IF NOT EXISTS pricing_tier TEXT")
            cur.execute("SELECT pricing_tier FROM public.cc_reseller_tenants WHERE id=%s",(tenant_id,))
            row=cur.fetchone()
    tier=row[0] if row else None
    return {"tier":tier,"discount_percent":WHOLESALE_TIERS.get(tier),
            "food_only":True,"full_service_fee_percent":15,
            "excluded":["delivery","staffing","equipment","rentals","extras"],
            "market_price_requires_approval":True}
class WholesaleEstimate(BaseModel):
    lines: list[dict] = Field(min_length=1,max_length=100)
    full_service: bool = False
@app.post("/api/reseller/wholesale-estimate")
def reseller_wholesale_estimate(data:WholesaleEstimate,request:Request):
    from decimal import Decimal,ROUND_HALF_UP
    tenant_id=reseller_identity(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("ALTER TABLE public.cc_reseller_tenants ADD COLUMN IF NOT EXISTS pricing_tier TEXT")
            cur.execute("SELECT pricing_tier FROM public.cc_reseller_tenants WHERE id=%s",(tenant_id,))
            row=cur.fetchone()
    tier=row[0] if row else None
    if tier not in WHOLESALE_TIERS: raise HTTPException(403,"Wholesale tier not assigned by owner")
    excluded_ids=[1030,1031,1032,1033,1034,1035,1036]
    minimum_by_category={"1000":15,"1001":15,"1002":15,"1003":20,"1004":20,"1005":20,"1006":20,"1007":20,"1008":20,"1022":15,"1023":15,"1024":15}
    reference={"1000":[14.95,"person"],"1001":[17.95,"person"],"1002":[21.95,"person"],"1003":[16.95,"person"],"1004":[22.95,"person"],"1005":[29.95,"person"],"1006":[18.95,"person"],"1007":[23.95,"person"],"1008":[28.95,"person"],"1009":[14.95,"person"],"1010":[10.95,"person"],"1011":[10.95,"person"],"1012":[14.95,"person"],"1013":[10.95,"person"],"1014":[10.95,"person"],"1017":[8.95,"person"],"1018":[11.95,"person"],"1019":[14.95,"person"],"1020":[8.95,"person"],"1021":[10.95,"person"],"1022":[10.95,"person"],"1023":[14.95,"person"],"1024":[18.95,"person"],"1025":[3.5,"person"],"1026":[4.95,"person"],"1027":[4.95,"person"],"1028":[5.95,"person"],"1029":[7.95,"person"],"1030":[2.95,"person"],"1031":[4.95,"person"],"1032":[3,"person"],"1033":[4,"person"],"1034":[34.95,"person"],"1035":[41.95,"person"],"1036":[47.5,"person"],"2037":[60,"half pan"],"2038":[105,"full pan"],"2039":[65,"half pan"],"2040":[115,"full pan"],"2041":[80,"half pan"],"2042":[135,"full pan"],"2043":[80,"half pan"],"2044":[135,"full pan"],"2045":[70,"half pan"],"2046":[120,"full pan"],"2047":[70,"half pan"],"2048":[120,"full pan"],"2049":[80,"half pan"],"2050":[135,"full pan"],"2051":[65,"half pan"],"2052":[115,"full pan"],"2053":[60,"half pan"],"2054":[100,"full pan"],"2055":[70,"half pan"],"2056":[120,"full pan"],"2057":[50,"half pan"],"2058":[85,"full pan"],"2059":[50,"half pan"],"2060":[85,"full pan"],"2061":[40,"half pan"],"2062":[70,"full pan"],"2063":[40,"half pan"],"2064":[70,"full pan"],"2065":[35,"half pan"],"2066":[60,"full pan"],"2067":[35,"half pan"],"2068":[60,"full pan"],"2069":[40,"half pan"],"2070":[70,"full pan"],"2071":[35,"half pan"],"2072":[60,"full pan"],"2073":[35,"half pan"],"2074":[60,"full pan"],"2075":[40,"half pan"],"2076":[70,"full pan"],"2077":[40,"half pan"],"2078":[70,"full pan"],"2079":[35,"half pan"],"2080":[60,"full pan"],"2081":[30,"half pan"],"2082":[55,"full pan"],"2083":[35,"half pan"],"2084":[60,"full pan"],"4000":[60,"order"],"4001":[70,"order"],"4002":[50,"order"],"4003":[45,"order"],"4004":[75,"order"],"4005":[55,"order"],"4006":[90,"order"],"4007":[35,"order"],"4008":[65,"order"],"4009":[60,"order"],"4010":[105,"order"],"5001":[12.95,"person"],"5002":[15.95,"person"]}
    subtotal=Decimal("0")
    details=[]
    for line in data.lines:
        try:
            item_id=str(int(line["master_id"]))
            quantity=int(line["quantity"])
        except (KeyError,TypeError,ValueError): raise HTTPException(400,"Invalid menu item or quantity")
        if quantity<1 or quantity>10000: raise HTTPException(400,"Invalid quantity")
        if item_id not in reference or int(item_id) in excluded_ids: raise HTTPException(400,"This item requires a manual wholesale quote")
        if item_id in minimum_by_category and quantity<minimum_by_category[item_id]:
            raise HTTPException(400,"Guest count is below the catering minimum")
        unit_price=Decimal(str(reference[item_id][0]))
        base=unit_price*quantity
        discounted=(base*Decimal(100-WHOLESALE_TIERS[tier])/100).quantize(Decimal(".01"),rounding=ROUND_HALF_UP)
        subtotal+=discounted
        details.append({"master_id":int(item_id),"quantity":quantity,"unit":reference[item_id][1],
                        "reference_food_subtotal":str(base),"discounted_food_subtotal":str(discounted)})
    if any(str(line.get("master_id")) in ["2037","2038","2039","2040","2041","2042","2043","2044","2045","2046","2047","2048","2049","2050","2051","2052","2053","2054","2055","2056","2057","2058","2059","2060","2061","2062","2063","2064","2065","2066","2067","2068","2069","2070","2071","2072","2073","2074","2075","2076","2077","2078","2079","2080","2081","2082","2083","2084","4000","4001","4002","4003","4004","4005","4006","4007","4008","4009","4010"] for line in data.lines) and subtotal<Decimal("150"):
        raise HTTPException(400,"À la carte order is below the $150 minimum; request manual review")
    fee=(subtotal*Decimal(".15")).quantize(Decimal(".01"),rounding=ROUND_HALF_UP) if data.full_service else Decimal("0")
    return {"tier":tier,"discount_percent":WHOLESALE_TIERS[tier],"lines":details,
            "discounted_food_subtotal":str(subtotal),"full_service_fee":str(fee),
            "estimated_total_excluding_extras":str(subtotal+fee),
            "estimate_only":True,"requires_supplier_approval":True,
            "excluded":["delivery","staffing","equipment","rentals","extras"]}

@app.post("/api/admin/resellers/{tenant_id}/revoke-access")
def revoke_reseller_access(tenant_id:int,request:Request):
    admin_auth(request)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("SELECT id FROM public.cc_reseller_tenants WHERE id=%s",(tenant_id,))
            if not cur.fetchone(): raise HTTPException(404,"Reseller not found")
            cur.execute("DELETE FROM public.cc_reseller_access WHERE tenant_id=%s",(tenant_id,))
            count=cur.rowcount
    return {"tenant_id":tenant_id,"revoked_credentials":count}
@app.post("/api/admin/resellers/{tenant_id}/rotate-access")
def rotate_reseller_access(tenant_id:int,request:Request):
    admin_auth(request)
    token=secrets.token_urlsafe(48)
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            reseller_schema(cur)
            cur.execute("SELECT id FROM public.cc_reseller_tenants WHERE id=%s AND status='approved'",(tenant_id,))
            if not cur.fetchone(): raise HTTPException(404,"Approved reseller not found")
            cur.execute("DELETE FROM public.cc_reseller_access WHERE tenant_id=%s",(tenant_id,))
            cur.execute("""INSERT INTO public.cc_reseller_access(tenant_id,token_hash,expires_at)
                VALUES(%s,%s,NOW()+INTERVAL '30 days')""",(tenant_id,hashlib.sha256(token.encode()).hexdigest()))
    return {"tenant_id":tenant_id,"invitation_token":token,"expires_in_days":30,
            "warning":"Copy and deliver securely; previous credentials are revoked."}
