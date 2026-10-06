# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   uvicorn app:app --app-dir src --reload
   ```

3. Configure teacher accounts in `src/teachers.json`. Each entry has a username
   and a PBKDF2-SHA256 password hash; never put plaintext passwords in this file.
   Generate a hash with Python:

   ```
   python - <<'PY'
   import getpass
   import hashlib
   import secrets

   password = getpass.getpass("Teacher password: ").encode("utf-8")
   salt = secrets.token_bytes(16)
   iterations = 600000
   digest = hashlib.pbkdf2_hmac("sha256", password, salt, iterations).hex()
   print(f"pbkdf2_sha256${iterations}${salt.hex()}${digest}")
   PY
   ```

   Add the output as `password_hash` for a teacher in the JSON file, then restart
   the server. Set `COOKIE_SECURE=true` when serving the app over HTTPS.

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                     | Log in as a teacher and start a session                             |
| GET    | `/auth/session`                                                   | Check the current teacher session                                   |
| POST   | `/auth/logout`                                                    | End the current teacher session                                     |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up a student (teachers only)                                   |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teachers only)                             |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.

Activity rosters remain publicly viewable. Only authenticated teachers can sign
up or unregister students. Teacher password hashes are loaded from
`src/teachers.json`; login sessions expire after eight hours or when the teacher
logs out.
