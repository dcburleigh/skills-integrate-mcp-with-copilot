import hashlib
import json
import unittest
from copy import deepcopy
from urllib.parse import unquote, urlsplit

from src import app as app_module


class AdminModeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_teachers = app_module.teachers
        self.original_sessions = app_module.teacher_sessions.copy()
        self.original_activities = deepcopy(app_module.activities)
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        iterations = 120_000
        digest = hashlib.pbkdf2_hmac(
            "sha256", b"school-password", salt, iterations
        ).hex()
        app_module.teachers = [{
            "username": "teacher",
            "password_hash": (
                f"pbkdf2_sha256${iterations}${salt.hex()}${digest}"
            ),
        }]
        app_module.teacher_sessions.clear()

    async def asyncTearDown(self):
        app_module.teachers = self.original_teachers
        app_module.teacher_sessions.clear()
        app_module.teacher_sessions.update(self.original_sessions)
        app_module.activities.clear()
        app_module.activities.update(self.original_activities)

    async def request(self, method, target, body=None, cookie=None):
        parsed = urlsplit(target)
        headers = []
        raw_body = b""
        if body is not None:
            raw_body = json.dumps(body).encode("utf-8")
            headers.append((b"content-type", b"application/json"))
        if cookie:
            headers.append((b"cookie", cookie.encode("latin-1")))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": unquote(parsed.path),
            "raw_path": parsed.path.encode("ascii"),
            "query_string": parsed.query.encode("ascii"),
            "root_path": "",
            "headers": headers,
            "client": ("testclient", 123),
            "server": ("testserver", 80),
        }
        request_sent = False
        messages = []

        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {
                    "type": "http.request",
                    "body": raw_body,
                    "more_body": False,
                }
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)

        await app_module.app(scope, receive, send)
        response_start = next(
            message for message in messages
            if message["type"] == "http.response.start"
        )
        response_body = b"".join(
            message.get("body", b"")
            for message in messages
            if message["type"] == "http.response.body"
        )
        return (
            response_start["status"],
            response_start["headers"],
            json.loads(response_body) if response_body else None,
        )

    async def test_roster_is_public_but_registration_changes_require_teacher(self):
        status, _, roster = await self.request("GET", "/activities")
        self.assertEqual(status, 200)
        self.assertIn("Chess Club", roster)

        signup_target = "/activities/Chess%20Club/signup?email=student%40example.edu"
        status, _, _ = await self.request("POST", signup_target)
        self.assertEqual(status, 401)

        unregister_target = "/activities/Chess%20Club/unregister?email=student%40example.edu"
        status, _, _ = await self.request("DELETE", unregister_target)
        self.assertEqual(status, 401)

        status, headers, _ = await self.request(
            "POST",
            "/auth/login",
            {"username": "teacher", "password": "school-password"},
        )
        self.assertEqual(status, 200)
        set_cookie = next(value for name, value in headers if name == b"set-cookie")
        cookie = set_cookie.decode("latin-1").split(";", 1)[0]

        status, _, _ = await self.request("POST", signup_target, cookie=cookie)
        self.assertEqual(status, 200)
        status, _, updated_roster = await self.request("GET", "/activities")
        self.assertEqual(status, 200)
        self.assertIn(
            "student@example.edu",
            updated_roster["Chess Club"]["participants"],
        )

        status, _, _ = await self.request("DELETE", unregister_target, cookie=cookie)
        self.assertEqual(status, 200)
        status, _, updated_roster = await self.request("GET", "/activities")
        self.assertEqual(status, 200)
        self.assertNotIn(
            "student@example.edu",
            updated_roster["Chess Club"]["participants"],
        )

    async def test_invalid_login_and_logout_revoke_session(self):
        status, _, _ = await self.request(
            "POST",
            "/auth/login",
            {"username": "teacher", "password": "wrong-password"},
        )
        self.assertEqual(status, 401)

        status, headers, _ = await self.request(
            "POST",
            "/auth/login",
            {"username": "teacher", "password": "school-password"},
        )
        self.assertEqual(status, 200)
        set_cookie = next(value for name, value in headers if name == b"set-cookie")
        cookie = set_cookie.decode("latin-1").split(";", 1)[0]

        status, _, _ = await self.request("POST", "/auth/logout", cookie=cookie)
        self.assertEqual(status, 200)
        status, _, _ = await self.request(
            "POST",
            "/activities/Chess%20Club/signup?email=student%40example.edu",
            cookie=cookie,
        )
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
