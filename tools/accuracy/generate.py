"""Generates the accuracy corpus (milestone M6.1, ADR 0016).

Writes fixtures/accuracy/corpus.jsonl: one JSON object per line with
  text    the synthetic Spanish text,
  expect  classes that must be found (empty for a negative),
  allow   classes that may be found without counting as false positives,
  group   what the text is, for the report.

Every value is invented. Check digits are computed here, independently of the Rust code,
so the corpus tests the detectors rather than repeating them. Deterministic: a fixed seed,
so the file only changes when this script does. Run from the repository root:
  python3 -I tools/accuracy/generate.py
"""

import base64
import json
import random
import string
import sys

SEED = 20261126
DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
CIF_LETTERS = "JABCDEFGHI"

rng = random.Random(SEED)


def digits(n):
    return "".join(rng.choice(string.digits) for _ in range(n))


def dni():
    number = rng.randrange(10_000_000, 100_000_000)
    return f"{number:08d}{DNI_LETTERS[number % 23]}"


def wrong_dni():
    number = rng.randrange(10_000_000, 100_000_000)
    right = DNI_LETTERS[number % 23]
    letter = rng.choice([c for c in DNI_LETTERS if c != right])
    return f"{number:08d}{letter}"


def nie():
    prefix = rng.choice("XYZ")
    number = rng.randrange(0, 10_000_000)
    value = "XYZ".index(prefix) * 10_000_000 + number
    return f"{prefix}{number:07d}{DNI_LETTERS[value % 23]}"


def cif_control(seven):
    a = sum(int(seven[i]) for i in (1, 3, 5))
    b = 0
    for i in (0, 2, 4, 6):
        doubled = int(seven[i]) * 2
        b += doubled // 10 + doubled % 10
    return (10 - (a + b) % 10) % 10


def cif():
    first = rng.choice("ABEH")  # control must be a digit
    seven = digits(7)
    return f"{first}{seven}{cif_control(seven)}"


def mod97(text):
    rearranged = text[4:] + text[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97


def iban_es():
    account = digits(20)
    check = 98 - mod97(f"ES00{account}")
    return f"ES{check:02d}{account}"


def iban_print(iban):
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


def wrong_iban():
    iban = iban_es()
    last = str((int(iban[-1]) + 1) % 10)
    return iban[:-1] + last


def luhn_ok(number):
    total = 0
    for i, c in enumerate(reversed(number)):
        d = int(c)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card():
    prefix = rng.choice(["4", "51", "52", "37"])
    length = 15 if prefix == "37" else 16
    body = prefix + digits(length - len(prefix) - 1)
    for last in string.digits:
        if luhn_ok(body + last):
            return body + last
    raise AssertionError


def card_print(number):
    return " ".join(number[i:i + 4] for i in range(0, len(number), 4))


def wrong_card():
    number = card()
    last = str((int(number[-1]) + 1) % 10)
    return number[:-1] + last


def mobile():
    return rng.choice("67") + digits(8)


def landline():
    return rng.choice("89") + digits(8)


def email():
    user = rng.choice(["ana", "luis.garcia", "m.lopez", "soporte", "jperez82", "carmen_ruiz"])
    domain = rng.choice(["example.es", "correo.example.com", "empresa.example.org"])
    return f"{user}@{domain}"


def b62(n):
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def secrets():
    upper = string.ascii_uppercase + string.digits
    return [
        "AKIA" + "".join(rng.choice(upper) for _ in range(16)),
        "ghp_" + b62(36),
        "sk-proj-" + b62(40),
        "sk-ant-api03-" + b62(40),
        "xoxb-" + digits(12) + "-" + b62(24),
        "rsg_" + b62(43),
    ]


def hexstr(n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def uuid():
    h = hexstr(32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


rows = []


def add(text, expect=(), allow=(), group=""):
    rows.append({"text": text, "expect": sorted(set(expect)), "allow": sorted(set(allow)), "group": group})


# --- Negatives: look sensitive, are not (design document, "Pruebas") ---------------------------
NEGATIVE_TEMPLATES = [
    ("order", lambda: f"Pedido {digits(8)} enviado ayer por mensajería."),
    ("order", lambda: f"Su pedido PED-2026-{digits(6)} está en reparto."),
    ("order", lambda: f"Nº de pedido: {digits(10)}"),
    ("invoice", lambda: f"Adjunto la factura FAC-2026/{digits(4)} del mes de noviembre."),
    ("invoice", lambda: f"Ref. B-{digits(7)}"),
    ("postcode", lambda: f"Enviar a CP {rng.choice(['28', '41', '08', '46', '29'])}{digits(3)}, Sevilla."),
    ("date", lambda: f"La reunión es el {rng.randrange(1, 29):02d}/{rng.randrange(1, 13):02d}/2026 a las {rng.randrange(8, 20)}:{rng.choice(['00', '30'])}."),
    ("plate", lambda: f"Matrícula {digits(4)} {''.join(rng.choice('BCDFGHJKLMNPRSTVWXYZ') for _ in range(3))}"),
    ("amount", lambda: f"Importe total: {rng.randrange(1, 99)}.{digits(3)},{digits(2)} €"),
    ("case", lambda: f"Expediente 2026/{digits(5)}"),
    ("commit", lambda: f"Corregido en el commit {hexstr(40)}."),
    ("uuid", lambda: f"Identificador de sesión {uuid()}"),
    ("isbn", lambda: f"ISBN 978-84-{digits(4)}-{digits(3)}-{digits(1)}"),
    ("tracking", lambda: f"Seguimiento: ES{digits(13)}"),
    ("version", lambda: f"Actualiza a la versión {rng.randrange(1, 9)}.{rng.randrange(0, 20)}.{rng.randrange(0, 50)}"),
    ("ip", lambda: f"El servidor 10.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)} no responde."),
    ("wrong_dni", lambda: f"El DNI {wrong_dni()} no es válido."),
    ("wrong_iban", lambda: f"Cuenta {iban_print(wrong_iban())}"),
    ("wrong_card", lambda: f"Tarjeta {card_print(wrong_card())}"),
    ("time", lambda: f"Duración {rng.randrange(1, 9)}h {rng.randrange(0, 60)}min"),
    ("prose", lambda: rng.choice([
        "Gracias por contactar con nosotros, le responderemos en breve.",
        "El informe trimestral muestra un crecimiento del 4,5 % en ventas.",
        "Recuerda revisar la configuración antes de desplegar.",
        "La entrega se retrasará por la huelga de transportes.",
        "Por favor, confirme su asistencia antes del viernes.",
    ])),
]
for _ in range(300):
    group, make = rng.choice(NEGATIVE_TEMPLATES)
    # A commit hash may be flagged as a secret candidate (design document, Annex G.6).
    allow = ["secret_candidate"] if group in ("commit", "uuid", "tracking") else []
    add(make(), allow=allow, group=group)

# The exact examples of Annex G.6.
for text in ["Pedido 12345678 enviado", "Ref. B-1234567", "CP 41001", "Expediente 2026/00412"]:
    add(text, group="g6")
add("Commit 0f3a9c2e5b7d4180a6c3e9f1b2d4a6c8e0f1a3b5", allow=["secret_candidate"], group="g6")
add("Sesión 3f2b8c1e-4d5a-4b6c-9e7f-0a1b2c3d4e5f", allow=["secret_candidate"], group="g6")

# --- Positives: sensitive in format, invented ---------------------------------------------------
POSITIVE_TEMPLATES = [
    ("dni", lambda: (f"Mi DNI es {dni()}.", ["es_id"])),
    ("dni_dots", lambda: ((lambda d: f"DNI: {d[:2]}.{d[2:5]}.{d[5:8]}-{d[8]}")(dni()), ["es_id"])),
    ("nie", lambda: (f"NIE {nie()}", ["es_id"])),
    ("cif", lambda: (f"Facturar a la empresa con CIF {cif()}", ["es_id"])),
    ("iban", lambda: (f"Transferencia a {iban_print(iban_es())}", ["iban"])),
    ("iban_compact", lambda: (f"IBAN {iban_es()}", ["iban"])),
    ("card", lambda: (f"Pago con la tarjeta {card_print(card())}", ["card"])),
    ("mobile", lambda: ((lambda m: f"Llámame al {m[:3]} {m[3:5]} {m[5:7]} {m[7:]}")(mobile()), ["phone"])),
    ("mobile_prefix", lambda: (f"Mi móvil: +34 {mobile()}", ["phone"])),
    ("landline", lambda: (f"Teléfono de la oficina {landline()}", ["phone"])),
    ("email", lambda: (f"Escríbeme a {email()} cuando puedas.", ["email"])),
    ("secret", lambda: (f"La clave es {rng.choice(secrets())}", ["secret"])),
    ("dni_base64", lambda: (base64.b64encode(f"DNI {dni()}".encode()).decode(), ["es_id"])),
    ("dni_fullwidth", lambda: ("".join(chr(ord(c) + 0xFEE0) for c in dni()), ["es_id"])),
    ("secret_zero_width", lambda: ((lambda s: s[:3] + "​" + s[3:])("ghp_" + b62(36)), ["secret", "invisible_text"])),
    ("mixed", lambda: (f"Cliente {dni()}, cuenta {iban_print(iban_es())}, correo {email()}", ["es_id", "iban", "email"])),
    # Known gap (ADR 0010): a value glued to letters is not found. Kept to measure it.
    ("gap_glued", lambda: (f"DNI{dni()}", ["es_id"])),
]
for _ in range(100):
    group, make = rng.choice(POSITIVE_TEMPLATES)
    text, expect = make()
    # A phone inside a longer number, or an entropy flag on encoded text, is not a mistake.
    allow = ["secret_candidate", "phone"] if group in ("dni_base64", "secret", "secret_zero_width") else []
    add(text, expect=expect, allow=allow, group=group)

out = "fixtures/accuracy/corpus.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
print(f"{out}: {len(rows)} texts ({sum(1 for r in rows if not r['expect'])} negatives)", file=sys.stderr)
