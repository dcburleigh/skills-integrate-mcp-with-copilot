"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

TEACHERS_FILE = Path(__file__).with_name("teachers.json")
SESSION_COOKIE = "teacher_session"
SESSION_LIFETIME_SECONDS = 8 * 60 * 60
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "").lower() == "true"
teacher_sessions = {}


def _load_teachers():
    try:
        with TEACHERS_FILE.open(encoding="utf-8") as teacher_file:
            config = json.load(teacher_file)
    except FileNotFoundError:
        return []

    if not isinstance(config, dict) or not isinstance(config.get("teachers"), list):
        raise RuntimeError("teachers.json must contain a 'teachers' list")
    return config["teachers"]


teachers = _load_teachers()


class TeacherCredentials(BaseModel):
    username: str
    password: str


def _verify_password(password, password_hash):
    try:
        scheme, iteration_text, salt_hex, digest_hex = password_hash.split("$", 3)
        iterations = int(iteration_text)
        if scheme != "pbkdf2_sha256" or iterations < 100_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(actual_digest, expected_digest)


def _authenticate_teacher(username, password):
    for teacher in teachers:
        stored_username = teacher.get("username")
        if (isinstance(stored_username, str)
                and hmac.compare_digest(stored_username, username)
                and _verify_password(password, teacher.get("password_hash"))):
            return stored_username
    return None


def _get_session_username(request):
    token = request.cookies.get(SESSION_COOKIE)
    session = teacher_sessions.get(token)
    if not session:
        return None

    username, expires_at = session
    if expires_at <= time.time():
        teacher_sessions.pop(token, None)
        return None
    return username


def require_teacher(request: Request):
    username = _get_session_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


@app.post("/auth/login")
def login(credentials: TeacherCredentials, response: Response):
    username = _authenticate_teacher(credentials.username, credentials.password)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    teacher_sessions[token] = (username, time.time() + SESSION_LIFETIME_SECONDS)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"username": username}


@app.get("/auth/session")
def get_auth_session(request: Request):
    username = _get_session_username(request)
    return {"authenticated": username is not None, "username": username}


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        teacher_sessions.pop(token, None)
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )
    return {"message": "Logged out"}

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, email: str, _teacher: str = Depends(require_teacher)
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, _teacher: str = Depends(require_teacher)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
