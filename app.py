from flask import Flask, render_template, redirect, request, url_for, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
import os
import datetime
import pytz

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow http

app = Flask(__name__)
app.secret_key = "challabhardvajsecretkey"

GOOGLE_CLIENT_ID = "990077513200-gqs0pb74pqri69v49jebkbe9vnk19lmj.apps.googleusercontent.com"

flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def indian_time():
    tz = pytz.timezone("Asia/Kolkata")
    now = datetime.datetime.now(tz)
    return now.strftime("%Y-%m-%d %H:%M:%S")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return "State mismatch", 400

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["user"] = {
        "name": id_info.get("name"),
        "email": id_info.get("email"),
        "picture": id_info.get("picture")
    }

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template("dashboard.html",
                           user=session["user"],
                           time=indian_time())


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/pattern", methods=["GET", "POST"])
def pattern():
    if "user" not in session:
        return redirect(url_for("home"))

    output = None

    if request.method == "POST":
        try:
            lines = int(request.form["lines"])
            output = generate_pattern(lines)
        except:
            output = "Invalid number."

    return render_template("pattern.html", output=output)


def generate_pattern(lines):
    """Generate the diamond pattern with SOLUTIONSFORMULAQ string"""
    S = "SOLUTIONSFORMULAQ"
    n = len(S)
    mid = n // 2
    
    
    top_half_lines = (lines // 2) + 1
    
    result = []
    
    
    for i in range(top_half_lines):
        left = mid - i
        right = mid + i
        
        
        left_wrapped = left % n
        right_wrapped = right % n
        
        
        if left == right:
            result.append(S[left_wrapped])
        else:
            
            if right < n:
                
                if i % 2 == 1:
                    
                    inside = right - left - 1
                    line = S[left] + "-"*inside + S[right]
                else:
                    
                    line = S[left:right+1]
            else:
                
                length = right - left + 1
                seg = ""
                for offset in range(length):
                    idx = (left + offset) % n
                    seg += S[idx]
                
               
                if i % 2 == 1 and len(seg) > 1:
                    line = seg[0] + "-"*(len(seg)-2) + seg[-1]
                else:
                    line = seg
            
            result.append(line)
    
   
    bottom = result[:-1][::-1]
    all_lines = result + bottom
    
   
    width = max(len(x) for x in all_lines)
    centered = [x.center(width) for x in all_lines]
    
    return "\n".join(centered)