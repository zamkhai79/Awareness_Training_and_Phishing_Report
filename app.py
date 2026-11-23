import os, sqlite3, secrets, time
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('PHISHGUARD_DB', os.path.join(BASE,'phishguard.db'))
app = Flask(__name__)

def load_secret_key():
    """Use SECRET_KEY if set, else a key persisted to .secret_key so sessions survive restarts."""
    env=os.environ.get('SECRET_KEY')
    if env:return env
    path=os.path.join(BASE,'.secret_key')
    try:
        with open(path) as f:
            key=f.read().strip()
            if len(key)>=32:return key
    except OSError:pass
    key=secrets.token_hex(32)
    try:
        with open(path,'w') as f:f.write(key)
    except OSError:pass
    return key

# Set PHISHGUARD_HTTPS=1 when served over HTTPS to mark the session cookie Secure and send HSTS.
HTTPS=os.environ.get('PHISHGUARD_HTTPS')=='1'
app.config.update(SECRET_KEY=load_secret_key(),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=HTTPS,MAX_CONTENT_LENGTH=100_000)

LOCK_MAX_FAILURES=5      # failed attempts allowed per username...
LOCK_WINDOW_SECONDS=900  # ...within this window (15 min) before sign-in is blocked
IP_MAX_FAILURES=20       # failed attempts allowed per IP in the same window
DUMMY_HASH=generate_password_hash('not-a-real-password')  # equalizes timing for unknown users

QUESTIONS = [
 ('IT Support <support@company-security-example.com>', 'URGENT: Microsoft 365 account expires in 30 minutes', 'Click the verification link and enter your password immediately or your account will be disabled.', 'phishing', 'Urgency, a threatening deadline, and an unverified sender domain are warning signs.'),
 ('Events Team <events@internal.example>', 'Updated meeting agenda', 'The agenda is available in the organization’s established document portal. Please open it using your normal bookmark.', 'likely_legitimate', 'No urgent credential request or unexpected attachment appears here; still verify unusual messages.'),
 ('Payroll <payroll@benefits-security-example.com>', 'Direct deposit failed', 'Reply with your bank account number and password to avoid a delayed payment.', 'phishing', 'Requests for passwords and financial details by email are strong red flags.'),
 ('Executive Office <executive@company-ceo-example.com>', 'Confidential gift cards', 'I am in a meeting. Purchase five gift cards immediately and send me the codes.', 'phishing', 'Impersonation, urgency, and gift-card requests indicate a likely scam.'),
 ('HR Team <hr@company-benefits-example.com>', 'Open enrollment reminder', 'Open enrollment closes Friday. Log in through the HR portal link on the intranet home page to review your options.', 'likely_legitimate', 'It points to a known internal portal rather than a link in the email, and asks for no credentials.'),
 ('Package Delivery <track@parcel-delivery-example.net>', 'Delivery failed: pay $1.99 fee', 'We could not deliver your parcel. Pay a small redelivery fee at the link below within 12 hours or it will be returned.', 'phishing', 'Small fees, short deadlines, and unknown delivery links are common phishing tactics.'),
 ('IT Helpdesk <helpdesk@internal.example>', 'Scheduled maintenance Saturday', 'Email will be unavailable Saturday 1-3 AM for planned maintenance. No action is required.', 'likely_legitimate', 'It is informational, expects no action, and contains no links or credential requests.'),
 ('Security Alert <alert@secure-login-example.org>', 'Unusual sign-in detected', 'Someone signed in from another country. Confirm your identity by entering your username and password here.', 'phishing', 'Fake security alerts push you to enter credentials on a look-alike page.'),
 ('Finance <invoices@vendor-billing-example.com>', 'Invoice attached: payment overdue', 'Open the attached ZIP file to view your overdue invoice. Failure to pay today will incur penalties.', 'phishing', 'Unexpected ZIP attachments combined with pressure are typical malware delivery tactics.'),
 ('Facilities <facilities@internal.example>', 'Parking lot repainting', 'The north lot will be repainted Tuesday. Please use the south lot that day.', 'likely_legitimate', 'Routine notice with no links, attachments, or requests for information.'),
 ('Cloud Storage <share@docs-sharing-example.com>', 'A file was shared with you', 'Someone shared "Salary_2026.xlsx". Sign in with your work email password to view it.', 'phishing', 'Curiosity bait plus a sign-in request on an unfamiliar domain is a credential-harvesting pattern.'),
 ('Training Dept <training@internal.example>', 'Your annual security course is due', 'Please complete your annual security course by the end of the month using the learning platform you normally access.', 'likely_legitimate', 'It refers to your normal platform and gives a reasonable deadline with no pressure.'),
 ('Bank Support <support@bank-verify-example.com>', 'Account locked', 'Your account has been locked. Call the number in this email and provide your PIN to unlock it.', 'phishing', 'Banks do not ask for PINs by email or phone number provided in a message.'),
 ('Recruiter <jobs@dream-careers-example.com>', 'Work from home: $5,000 per week', 'No experience needed. Send your ID and bank details today to start earning.', 'phishing', 'Too-good-to-be-true offers asking for ID and bank details point to fraud.'),
 ('Manager <manager@internal.example>', 'Team lunch Thursday', 'Reminder that we have a team lunch Thursday at noon. Let me know about dietary needs when we meet.', 'likely_legitimate', 'Expected, internal, and harmless request with no links or sensitive data asked.'),
 ('Tax Authority <refund@tax-refund-example.com>', 'You are owed a refund', 'Claim your refund now by submitting your social security number and card details.', 'phishing', 'Government agencies do not request sensitive data through unsolicited email.'),
 ('Software Update <update@browser-patch-example.com>', 'Critical browser update', 'Download and run the attached installer immediately to fix a severe vulnerability.', 'phishing', 'Updates should come from official channels, not emailed installers.'),
 ('Payroll <payroll@internal.example>', 'Pay stub available', 'Your latest pay stub is available in the payroll system. Sign in through your usual bookmark.', 'likely_legitimate', 'It directs you to a known system without embedding a login link.'),
 ('CEO <ceo@company-ceo-example.net>', 'Quick favor', 'Are you at your desk? I need you to wire funds to a new vendor today. Keep this between us.', 'phishing', 'Secrecy, urgency, and wire requests from a look-alike domain suggest business email compromise.'),
 ('Social Media <security@social-account-example.com>', 'Your account will be deleted', 'Violation detected. Click here to appeal within 24 hours or lose your account permanently.', 'phishing', 'Threats of account deletion with short deadlines are classic scare tactics.'),
 ('Legal <legal@internal.example>', 'Policy update: acceptable use', 'The acceptable use policy has been updated. The new version is posted on the intranet policy page.', 'likely_legitimate', 'It references an internal page you can visit directly and asks for nothing sensitive.'),
 ('Lottery <winner@global-lottery-example.com>', 'You won $1,000,000', 'Reply with your full name, address, and bank account to receive your prize.', 'phishing', 'Unexpected prizes requiring personal details are scams.'),
 ('IT Security <security@internal.example>', 'Password manager rollout', 'We are rolling out a password manager next month. Instructions will be posted on the intranet. Never share your password with anyone.', 'likely_legitimate', 'It reinforces good practice and does not ask for credentials or immediate action.'),
 ('Vendor <accounts@supplier-update-example.com>', 'Updated bank details', 'Our bank details changed. Send all future payments to the new account below.', 'phishing', 'Unverified payment detail changes should be confirmed through a known contact before acting.'),
 ('VPN Service <vpn@remote-access-example.com>', 'VPN certificate expired', 'Download the new certificate from the link and enter your credentials to reconnect.', 'phishing', 'Unexpected links asking for credentials to fix access are suspicious; contact IT through known channels.'),
 ('Office Manager <office@internal.example>', 'Fire drill Wednesday', 'A routine fire drill is planned for Wednesday at 10 AM. Please follow the posted evacuation routes.', 'likely_legitimate', 'Routine, expected, and has no links, attachments, or sensitive requests.'),
 ('Charity <donate@relief-fund-example.org>', 'Urgent disaster relief', 'Donate now via gift card or cryptocurrency. Every minute counts.', 'phishing', 'Pressure and untraceable payment methods are signs of a scam.'),
 ('Calendar <invite@internal.example>', 'Invitation: Quarterly review', 'You are invited to the quarterly review on Monday. Details are in the calendar invite.', 'likely_legitimate', 'Expected internal invite from a known sender with no credential requests.'),
 ('Mailbox Admin <admin@mailbox-quota-example.com>', 'Mailbox full', 'Your mailbox is full. Click here and sign in to increase your storage or lose incoming mail.', 'phishing', 'Fake quota warnings drive users to credential-stealing pages.'),
 ('Wellness <wellness@internal.example>', 'Step challenge starts Monday', 'Join the optional step challenge. Sign up with the team lead if interested.', 'likely_legitimate', 'Optional, internal, and requests no sensitive data.'),
]
QUIZ_SIZE = 10

def pick_quiz(uid):
    """Pick QUIZ_SIZE question indexes, avoiding ones this user has already seen."""
    with connect() as c:
        seen={r[0] for r in c.execute('SELECT q_index FROM quiz_seen WHERE user_id=?',(uid,))}
        fresh=[i for i in range(len(QUESTIONS)) if i not in seen]
        if len(fresh)<QUIZ_SIZE:
            # Bank exhausted: reset history, but never repeat the immediately preceding set
            last={r[0] for r in c.execute('SELECT q_index FROM quiz_seen WHERE user_id=? ORDER BY id DESC LIMIT ?',(uid,QUIZ_SIZE))}
            c.execute('DELETE FROM quiz_seen WHERE user_id=?',(uid,))
            fresh=[i for i in range(len(QUESTIONS)) if i not in last] if len(QUESTIONS)-len(last)>=QUIZ_SIZE else list(range(len(QUESTIONS)))
    return secrets.SystemRandom().sample(fresh,QUIZ_SIZE)

def connect():
    c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def init_db():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('employee','analyst','admin')));
        CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), sender TEXT NOT NULL, subject TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','phishing','legitimate','needs_more_info')), analyst_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT);
        CREATE TABLE IF NOT EXISTS quiz_attempts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), score INTEGER NOT NULL, total INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS quiz_seen (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), q_index INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, username TEXT NOT NULL, ip TEXT NOT NULL, ok INTEGER NOT NULL, ts INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL);''')
        for username,password,role in [('employee','DemoEmployee!2026','employee'),('analyst','DemoAnalyst!2026','analyst'),('admin','DemoAdmin!2026','admin'),('HumanR','HumanResources1@','employee')]:
            c.execute('INSERT OR IGNORE INTO users(username,password_hash,role) VALUES (?,?,?)',(username,generate_password_hash(password),role))
        n=c.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        if not n:
            uid=c.execute("SELECT id FROM users WHERE username='employee'").fetchone()[0]
            for sender,subject,reason,status in [
                ('payroll@benefits-security-example.com','Direct deposit update','Unexpected banking information request','phishing'),
                ('support@company-security-example.com','Verify your account','Unrecognized login link and urgent deadline','pending')]:
                c.execute('INSERT INTO reports(user_id,sender,subject,reason,status,created_at) VALUES(?,?,?,?,?,?)',(uid,sender,subject,reason,status,now()))

EST = timezone(timedelta(hours=-5), 'EST')

def now(): return datetime.now(EST).strftime('%Y-%m-%d %H:%M:%S EST')

@app.template_filter('est')
def to_est(value):
    """Show stored timestamps in EST; converts older rows saved as UTC."""
    if value and value.endswith(' UTC'):
        dt=datetime.strptime(value[:-4],'%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc).astimezone(EST)
        return dt.strftime('%Y-%m-%d %H:%M:%S EST')
    return value or ''

@app.before_request
def before():
    g.user=None
    if 'uid' in session:
        with connect() as c: g.user=c.execute('SELECT id,username,role FROM users WHERE id=?',(session['uid'],)).fetchone()
    if 'csrf' not in session: session['csrf']=secrets.token_hex(24)
    if request.method=='POST' and not secrets.compare_digest(request.form.get('csrf',''),session['csrf']):abort(400,'Invalid CSRF token')

@app.context_processor
def globals_template(): return dict(current_user=g.user,csrf=session.get('csrf',''))

@app.after_request
def headers(r):
    if HTTPS:r.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    if g.get('user'):r.headers['Cache-Control']='no-store'
    r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='no-referrer'
    r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"
    return r

def login_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not g.user:return redirect(url_for('login'))
        return fn(*a,**kw)
    return wrapped

def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*a,**kw):
            if g.user['role'] not in allowed:abort(403)
            return fn(*a,**kw)
        return wrapped
    return deco

def audit(actor,action,target):
    with connect() as c:c.execute('INSERT INTO audit(actor_id,action,target,created_at) VALUES(?,?,?,?)',(actor,action,target,now()))

def record_attempt(username,ip,ok):
    with connect() as c:c.execute('INSERT INTO login_attempts(username,ip,ok,ts,created_at) VALUES(?,?,?,?,?)',(username.lower(),ip,int(ok),int(time.time()),now()))

def login_locked(username,ip):
    """Block after too many failures per username or per IP since the last success within the window."""
    since=int(time.time())-LOCK_WINDOW_SECONDS
    with connect() as c:
        def failures(col,val):
            last=c.execute(f'SELECT COALESCE(MAX(ts),0) FROM login_attempts WHERE {col}=? AND ok=1',(val,)).fetchone()[0]
            return c.execute(f'SELECT COUNT(*) FROM login_attempts WHERE {col}=? AND ok=0 AND ts>?',(val,max(since,last))).fetchone()[0]
        return failures('username',username.lower())>=LOCK_MAX_FAILURES or failures('ip',ip)>=IP_MAX_FAILURES

@app.route('/')
def index():return redirect(url_for('dashboard') if g.user else url_for('login'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()[:100];ip=request.remote_addr or 'unknown'
        if login_locked(username,ip):
            flash('Too many failed attempts. Please wait 15 minutes and try again.','error')
            return render_template('login.html'),429
        with connect() as c: user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        # Always run one hash check so response time doesn't reveal whether the username exists
        ok=check_password_hash(user['password_hash'] if user else DUMMY_HASH,request.form.get('password',''))
        if user and ok:
            record_attempt(username,ip,True)
            session.clear();session['uid']=user['id'];session['csrf']=secrets.token_hex(24)
            audit(user['id'],'login','success')
            return redirect(url_for('dashboard'))
        record_attempt(username,ip,False)
        if user:audit(user['id'],'login_failed','wrong password')
        flash('Invalid username or password.','error')
    return render_template('login.html')

@app.route('/logout',methods=['POST'])
@login_required
def logout():audit(g.user['id'],'logout','success');session.clear();return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with connect() as c:
        stats={k:c.execute(q).fetchone()[0] for k,q in {'reports':'SELECT COUNT(*) FROM reports','pending':"SELECT COUNT(*) FROM reports WHERE status='pending'",'training':'SELECT COUNT(DISTINCT user_id) FROM quiz_attempts','phishing':"SELECT COUNT(*) FROM reports WHERE status='phishing'"}.items()}
        recent=c.execute('SELECT reports.*,users.username FROM reports JOIN users ON users.id=reports.user_id ORDER BY reports.id DESC LIMIT 5').fetchall()
    return render_template('dashboard.html',stats=stats,recent=recent)

@app.route('/training',methods=['GET','POST'])
@login_required
def training():
    if request.method=='POST':
        ids=session.get('quiz_ids')
        if not ids:flash('Start the training first.','error');return redirect(url_for('training'))
        qs=[QUESTIONS[i] for i in ids]
        if any(request.form.get('q'+str(i)) not in ('phishing','likely_legitimate') for i in range(len(qs))):flash('Answer every question.','error');return redirect(url_for('training'))
        score=sum(request.form['q'+str(i)]==q[3] for i,q in enumerate(qs))
        with connect() as c:
            c.execute('INSERT INTO quiz_attempts(user_id,score,total,created_at) VALUES(?,?,?,?)',(g.user['id'],score,len(qs),now()))
            c.executemany('INSERT INTO quiz_seen(user_id,q_index) VALUES(?,?)',[(g.user['id'],i) for i in ids])
        session.pop('quiz_ids',None)
        audit(g.user['id'],'quiz_completed',f'{score}/{len(qs)}')
        return render_template('results.html',score=score,total=len(qs),questions=qs,answers=[request.form['q'+str(i)] for i in range(len(qs))])
    # Reuse the in-progress set on refresh so unanswered attempts don't burn questions
    if not session.get('quiz_ids'):
        session['quiz_ids']=pick_quiz(g.user['id']);audit(g.user['id'],'quiz_started',f'{len(session["quiz_ids"])} questions')
    return render_template('training.html',questions=[QUESTIONS[i] for i in session['quiz_ids']])

@app.route('/report',methods=['GET','POST'])
@login_required
def report():
    if request.method=='POST':
        sender=request.form.get('sender','').strip()[:200];subject=request.form.get('subject','').strip()[:200];reason=request.form.get('reason','').strip()[:1500]
        if not all((sender,subject,reason)):
            flash('Complete all fields.','error');return redirect(url_for('report'))
        with connect() as c:
            cur=c.execute('INSERT INTO reports(user_id,sender,subject,reason,created_at) VALUES(?,?,?,?,?)',(g.user['id'],sender,subject,reason,now()));rid=cur.lastrowid
        audit(g.user['id'],'report_created',f'PH-{rid:04d}');flash(f'Report PH-{rid:04d} submitted to the analyst queue.','success');return redirect(url_for('my_reports'))
    return render_template('report.html')

@app.route('/my-reports')
@login_required
def my_reports():
    with connect() as c:items=c.execute('SELECT * FROM reports WHERE user_id=? ORDER BY id DESC',(g.user['id'],)).fetchall()
    return render_template('my_reports.html',items=items)

@app.route('/analyst')
@roles('analyst','admin')
def analyst():
    with connect() as c:items=c.execute('SELECT reports.*,users.username FROM reports JOIN users ON users.id=reports.user_id ORDER BY CASE reports.status WHEN "pending" THEN 0 ELSE 1 END,reports.id DESC').fetchall()
    return render_template('analyst.html',items=items)

@app.route('/analyst/<int:rid>',methods=['GET','POST'])
@roles('analyst','admin')
def review(rid):
    with connect() as c:item=c.execute('SELECT reports.*,users.username FROM reports JOIN users ON users.id=reports.user_id WHERE reports.id=?',(rid,)).fetchone()
    if not item:abort(404)
    if request.method=='POST':
        status=request.form.get('status','');note=request.form.get('note','').strip()[:1500]
        if status not in ('pending','phishing','legitimate','needs_more_info'):abort(400)
        with connect() as c:c.execute('UPDATE reports SET status=?,analyst_note=?,reviewed_by=?,reviewed_at=? WHERE id=?',(status,note,g.user['id'],now(),rid))
        audit(g.user['id'],'report_reviewed',f'PH-{rid:04d} -> {status}')
        flash('Classification saved.','success');return redirect(url_for('analyst'))
    return render_template('review.html',item=item)

@app.route('/admin')
@roles('admin')
def admin():
    with connect() as c:
        users=c.execute('SELECT users.username,users.role,COUNT(quiz_attempts.id) attempts,MAX(100*quiz_attempts.score/quiz_attempts.total) best FROM users LEFT JOIN quiz_attempts ON users.id=quiz_attempts.user_id GROUP BY users.id ORDER BY users.username').fetchall()
        logs=c.execute('SELECT audit.*,users.username FROM audit JOIN users ON audit.actor_id=users.id ORDER BY audit.id DESC LIMIT 200').fetchall()
        failed=c.execute('SELECT username,ip,created_at FROM login_attempts WHERE ok=0 ORDER BY id DESC LIMIT 50').fetchall()
    return render_template('admin.html',users=users,logs=logs,failed=failed)
init_db()
if __name__=='__main__':
    app.run(host='127.0.0.1',port=5000,debug=False)
