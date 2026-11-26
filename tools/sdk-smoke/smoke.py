"""Official OpenAI and Anthropic Python SDKs against Resguardo in front of the mock upstream.

Run through run.sh. Never contacts a real provider: it refuses any non-local URL, and the
Resguardo it talks to only accepts local upstreams.
"""

import os
import sys
from urllib.parse import urlparse

import anthropic
import openai

URL = os.environ["RESGUARDO_URL"]
KEY = os.environ["RESGUARDO_KEY"]
UNKNOWN_KEY = "rsg_" + "0" * 43
MESSAGES = [{"role": "user", "content": "hola"}]

if urlparse(URL).hostname not in ("127.0.0.1", "localhost", "::1"):
    sys.exit(f"refusing to run against a non-local URL: {URL}")

failures = 0


def check(name, condition, detail=""):
    global failures
    print(("ok   " if condition else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    if not condition:
        failures += 1


def error_code(error):
    """Resguardo's code from either error shape, as each SDK exposes it."""
    body = error.body if isinstance(error.body, dict) else {}
    inner = body.get("error", body)
    return inner.get("code") if isinstance(inner, dict) else None


# Retries off: one request, one receipt, and deterministic results.
def openai_client(key):
    return openai.OpenAI(api_key=key, base_url=f"{URL}/v1", max_retries=0)


def anthropic_client(**auth):
    return anthropic.Anthropic(base_url=URL, max_retries=0, **auth)


# --- Successful requests ----------------------------------------------------------------------

reply = openai_client(KEY).chat.completions.create(model="gpt-4.1-mini", messages=MESSAGES)
check("openai: chat completion through Resguardo", reply.choices[0].message.content == "echo: hola")

reply = anthropic_client(api_key=KEY).messages.create(
    model="claude-sonnet-5-5",
    max_tokens=16,
    messages=MESSAGES,
    extra_headers={"anthropic-beta": "smoke-test-2026-01-01"},
)
check("anthropic: message with the key in x-api-key", reply.content[0].text == "echo: hola")

# ANTHROPIC_AUTH_TOKEN style (what Claude Code sends as Authorization: Bearer).
reply = anthropic_client(auth_token=KEY).messages.create(
    model="claude-sonnet-5-5", max_tokens=16, messages=MESSAGES
)
check("anthropic: message with the key as a bearer token", reply.content[0].text == "echo: hola")

# --- Resguardo's own errors, as each SDK understands them -------------------------------------

try:
    openai_client(UNKNOWN_KEY).chat.completions.create(model="gpt-4.1-mini", messages=MESSAGES)
    check("openai: unknown key is rejected", False, "no error raised")
except openai.AuthenticationError as e:
    check("openai: unknown key -> AuthenticationError", error_code(e) == "UNKNOWN_KEY", str(e.body))

try:
    openai_client(KEY).chat.completions.create(model="gpt-5", messages=MESSAGES)
    check("openai: model outside the list is rejected", False, "no error raised")
except openai.PermissionDeniedError as e:
    check("openai: model outside the list -> PermissionDeniedError", error_code(e) == "MODEL_NOT_ALLOWED", str(e.body))

try:
    anthropic_client(api_key=UNKNOWN_KEY).messages.create(
        model="claude-sonnet-5-5", max_tokens=16, messages=MESSAGES
    )
    check("anthropic: unknown key is rejected", False, "no error raised")
except anthropic.AuthenticationError as e:
    check("anthropic: unknown key -> AuthenticationError", error_code(e) == "UNKNOWN_KEY", str(e.body))

try:
    anthropic_client(api_key=KEY).messages.create(
        model="claude-opus", max_tokens=16, messages=MESSAGES
    )
    check("anthropic: model outside the list is rejected", False, "no error raised")
except anthropic.PermissionDeniedError as e:
    check("anthropic: model outside the list -> PermissionDeniedError", error_code(e) == "MODEL_NOT_ALLOWED", str(e.body))

# --- Scanning, policy and redaction (M3) ------------------------------------------------------

DNI = [{"role": "user", "content": "Mi DNI es 12345678Z"}]
# Fake key from the AWS documentation, split so that secret scanners do not flag this file.
AWS_KEY = [{"role": "user", "content": "mi clave es " + "AKIA" + "IOSFODNN7EXAMPLE"}]

reply = openai_client(KEY).chat.completions.create(model="gpt-4.1-mini", messages=DNI)
content = reply.choices[0].message.content
check("openai: a DNI reaches the provider redacted", content == "echo: Mi DNI es [REDACTED:es_id:1]", content)

reply = anthropic_client(api_key=KEY).messages.create(
    model="claude-sonnet-5-5", max_tokens=16, messages=DNI
)
text = reply.content[0].text
check("anthropic: a DNI reaches the provider redacted", text == "echo: Mi DNI es [REDACTED:es_id:1]", text)

try:
    openai_client(KEY).chat.completions.create(model="gpt-4.1-mini", messages=AWS_KEY)
    check("openai: an AWS key is blocked", False, "no error raised")
except openai.PermissionDeniedError as e:
    check("openai: an AWS key -> PermissionDeniedError", error_code(e) == "SENSITIVE_DATA", str(e.body))

try:
    anthropic_client(api_key=KEY).messages.create(
        model="claude-sonnet-5-5", max_tokens=16, messages=AWS_KEY
    )
    check("anthropic: an AWS key is blocked", False, "no error raised")
except anthropic.PermissionDeniedError as e:
    check("anthropic: an AWS key -> PermissionDeniedError", error_code(e) == "SENSITIVE_DATA", str(e.body))

print(f"\n{'all checks passed' if failures == 0 else f'{failures} check(s) failed'}")
sys.exit(1 if failures else 0)
