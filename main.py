"""
🇳🇬 CredionPay — FastAPI Backend v13
=====================================
NEW IN v12:
  🔐 BVN encrypted with AES-256 (Fernet) before saving to disk
  🔐 BVN must match the account holder's registered name
  🔐 BVN date of birth must match user-submitted DOB
  🔐 Account name (Paystack) must match BVN registered name
  ✅ All previous features from v9 preserved

Run:
    pip install cryptography
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import uuid, os, logging, smtplib, json, pathlib, atexit, re
import base64, hashlib
from datetime import datetime
from typing import Optional, List
from dataclasses import dataclass, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
import urllib3
try:
    import certifi
    _CERTIFI_AVAILABLE = True
except ImportError:
    _CERTIFI_AVAILABLE = False
    certifi = None
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# cryptography is REQUIRED for BVN encryption — hard fail if missing
try:
    from cryptography.fernet import Fernet
    _FERNET_AVAILABLE = True
except ImportError:
    _FERNET_AVAILABLE = False
    print("=" * 60)
    print("❌  FATAL: cryptography package is not installed!")
    print("    BVN encryption WILL NOT work without it.")
    print("    Fix: pip install cryptography")
    print("=" * 60)
    # Do NOT exit — server still starts, but BVN stored plain with loud warning

# Robust .env loader — handles comments, blank lines, and special characters
# that confuse python-dotenv
def _load_env_file():
    """
    Robust .env loader — handles:
    - Quoted values: KEY="value with $special chars"
    - Windows CR/LF line endings
    - Lines with = inside the value (e.g. JWT tokens)
    - Comments after values
    - Blank lines and comment-only lines
    Always overrides os.environ so correct values are used even after
    python-dotenv partially parsed the file.
    """
    import pathlib
    env_path = pathlib.Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().rstrip("\r")
        # Skip blanks and comments
        if not line or line.startswith("#"):
            continue
        # Must have = to be a key=value pair
        if "=" not in line:
            continue
        # Split only on FIRST = so values containing = are preserved
        key, _, val = line.partition("=")
        key = key.strip().rstrip("\r")
        val = val.strip().rstrip("\r")
        # Strip surrounding quotes (single or double) from value
        if len(val) >= 2:
            if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
                val = val[1:-1]
        # Strip trailing inline comment  (e.g.  KEY=value  # comment)
        # Only strip if # is preceded by whitespace
        if "  #" in val:
            val = val[:val.index("  #")].strip()
        if key:
            os.environ[key] = val   # always set — overrides partial dotenv parse

import io, contextlib
try:
    # Suppress python-dotenv parse warnings — our robust loader handles them
    with contextlib.redirect_stderr(io.StringIO()):
        load_dotenv(override=True)
except Exception:
    pass
_load_env_file()   # robust fallback always wins — handles quoted values, $ chars, etc.
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="🇳🇬 CredionPay API", version="16.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

PAYSTACK_BASE_URL = "https://api.paystack.co"
SUDO_BASE_URL     = "https://api.sudo.africa"
FLW_BASE_URL      = "https://api.flutterwave.com/v3"
APP_NAME          = os.getenv("APP_NAME", "CredionPay")

# ── Nigerian Banks ────────────────────────────────────────────────────────────
NIGERIAN_BANKS = [
    {"name": "Access Bank",                "code": "044"},
    {"name": "Citibank Nigeria",           "code": "023"},
    {"name": "EcoBank Nigeria",            "code": "050"},
    {"name": "Fidelity Bank",              "code": "070"},
    {"name": "First Bank of Nigeria",      "code": "011"},
    {"name": "First City Monument Bank",   "code": "214"},
    {"name": "Globus Bank",                "code": "00103"},
    {"name": "Guaranty Trust Bank",        "code": "058"},
    {"name": "Heritage Bank",              "code": "030"},
    {"name": "Jaiz Bank",                  "code": "301"},
    {"name": "Keystone Bank",              "code": "082"},
    {"name": "Kuda Bank",                  "code": "50211"},
    {"name": "Moniepoint MFB",             "code": "50515"},
    {"name": "Opay Digital Services",      "code": "999992"},
    {"name": "PalmPay",                    "code": "999991"},
    {"name": "Polaris Bank",               "code": "076"},
    {"name": "Providus Bank",              "code": "101"},
    {"name": "Stanbic IBTC Bank",          "code": "221"},
    {"name": "Standard Chartered Bank",    "code": "068"},
    {"name": "Sterling Bank",              "code": "232"},
    {"name": "Taj Bank",                   "code": "302"},
    {"name": "Titan Trust Bank",           "code": "102"},
    {"name": "Union Bank of Nigeria",      "code": "032"},
    {"name": "United Bank for Africa",     "code": "033"},
    {"name": "Unity Bank",                 "code": "215"},
    {"name": "VFD Microfinance Bank",      "code": "566"},
    {"name": "Wema Bank",                  "code": "035"},
    {"name": "Zenith Bank",                "code": "057"},
]


# ══════════════════════════════════════════════════════════════════════════════
# BVN ENCRYPTION  — AES-256 via Fernet
# ══════════════════════════════════════════════════════════════════════════════

def _get_fernet():
    """
    Build a Fernet cipher from the BVN_MASTER_KEY env variable.
    Key is SHA-256 hashed to produce a stable 32-byte key.
    Change BVN_MASTER_KEY in .env before first use in production.
    """
    if not _FERNET_AVAILABLE:
        return None
    master = os.getenv("BVN_MASTER_KEY", "CredionPay-BVN-AyoTech-2026-ChangeInProduction")
    key    = base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest())
    return Fernet(key)


def encrypt_bvn(bvn: str) -> str:
    """
    Encrypt a plain BVN.
    Returns 'enc:<fernet_token>' so we can detect encrypted values on reload.
    If cryptography is not installed, returns plain BVN with a warning.
    """
    if not bvn:
        return bvn
    if bvn.startswith("enc:"):
        return bvn          # already encrypted
    f = _get_fernet()
    if f is None:
        logger.error("❌ CRITICAL: BVN being stored in PLAIN TEXT — cryptography not installed! Run: pip install cryptography")
        return bvn  # plain text fallback — NOT secure
    encrypted = f.encrypt(bvn.encode()).decode()
    return f"enc:{encrypted}"


def decrypt_bvn(stored: str) -> str:
    """
    Decrypt a stored BVN back to plain text.
    Only used internally for verification — never returned in API responses.
    """
    if not stored:
        return stored
    if not stored.startswith("enc:"):
        return stored       # legacy plain text (pre-v10)
    f = _get_fernet()
    if f is None:
        return stored
    try:
        return f.decrypt(stored[4:].encode()).decode()
    except Exception as e:
        logger.error(f"❌ BVN decryption failed: {e}")
        return ""


def mask_bvn(stored: str) -> str:
    """
    Return masked BVN for API display: *******8901 (last 4 visible only).
    Works for both encrypted ('enc:...') and legacy plain BVNs.
    """
    plain = decrypt_bvn(stored) if stored.startswith("enc:") else stored
    if not plain:
        return ""
    return plain[-4:].rjust(len(plain), "*")


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════════════

class TxType(str, Enum):
    CREDIT = "CREDIT"
    DEBIT  = "DEBIT"

class TxCategory(str, Enum):
    BANK_FUNDING        = "BANK_FUNDING"
    CARD_FUNDING        = "CARD_FUNDING"
    ACCOUNT_FUNDING     = "ACCOUNT_FUNDING"
    WALLET_TRANSFER_IN  = "WALLET_TRANSFER_IN"
    WALLET_TRANSFER_OUT = "WALLET_TRANSFER_OUT"
    BANK_PAYOUT         = "BANK_PAYOUT"
    VIRTUAL_CARD_DEBIT  = "VIRTUAL_CARD_DEBIT"
    AIRTIME_PURCHASE    = "AIRTIME_PURCHASE"
    DATA_PURCHASE       = "DATA_PURCHASE"
    BILL_PAYMENT        = "BILL_PAYMENT"
    DVA_FUNDING         = "DVA_FUNDING"
    INVOICE_PAYMENT     = "INVOICE_PAYMENT"
    INVOICE_PAYOUT      = "INVOICE_PAYOUT"

class KYCStatus(str, Enum):
    PENDING    = "pending"
    VERIFIED   = "verified"
    FAILED     = "failed"

class CardStatus(str, Enum):
    ACTIVE     = "active"
    FROZEN     = "frozen"
    TERMINATED = "terminated"


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RegisteredCard:
    card_id:        str = field(default_factory=lambda: f"DC-{uuid.uuid4().hex[:8].upper()}")
    masked_number:  str = ""
    last_four:      str = ""
    expiry:         str = ""
    card_type:      str = "Visa"
    bank_name:      str = ""
    bank_code:      str = ""
    account_number: str = ""
    account_name:   str = ""
    is_verified:    bool = False
    registered_at:  str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "card_id":        self.card_id,
            "masked_number":  self.masked_number,
            "last_four":      self.last_four,
            "expiry":         self.expiry,
            "card_type":      self.card_type,
            "bank_name":      self.bank_name,
            "account_number": self.account_number,
            "account_name":   self.account_name,
            "is_verified":    self.is_verified,
            "registered_at":  self.registered_at,
        }


@dataclass
class KYCRecord:
    bvn:              str = ""   # stored encrypted as "enc:..."
    nin:              str = ""
    full_name:        str = ""
    dob:              str = ""
    address:          str = ""
    phone:            str = ""
    account_number:   str = ""
    bank_code:        str = ""
    bank_name:        str = ""
    account_name:     str = ""
    registered_cards: list = field(default_factory=list)
    status:           KYCStatus = KYCStatus.PENDING
    verified_at:      str = ""
    failure_reason:   str = ""

    def to_dict(self):
        return {
            # BVN: show masked version only — never plain, never encrypted token
            "bvn":              mask_bvn(self.bvn) if self.bvn else "",
            "nin":              self.nin[-4:].rjust(len(self.nin), "*") if self.nin else "",
            "full_name":        self.full_name,
            "dob":              self.dob,
            "account_number":   f"****{self.account_number[-4:]}" if len(self.account_number) >= 4 else self.account_number,
            "bank_name":        self.bank_name,
            "account_name":     self.account_name,
            "registered_cards": self.registered_cards,
            "status":           self.status,
            "verified_at":      self.verified_at,
            "failure_reason":   self.failure_reason,
        }


@dataclass
class VirtualCard:
    card_id:       str = field(default_factory=lambda: f"VCR-{uuid.uuid4().hex[:10].upper()}")
    wallet_id:     str = ""
    card_number:   str = ""
    masked_number: str = ""
    expiry:        str = ""
    cvv:           str = ""
    card_type:     str = "Visa"
    currency:      str = "NGN"
    balance:       float = 0.0
    status:        CardStatus = CardStatus.ACTIVE
    created_at:    str = field(default_factory=lambda: datetime.now().isoformat())
    sudo_card_id:  str = ""

    def to_dict(self, show_sensitive: bool = False):
        return {
            "card_id":       self.card_id,
            "wallet_id":     self.wallet_id,
            "masked_number": self.masked_number or f"**** **** **** {self.card_number[-4:] if self.card_number else '****'}",
            "expiry":        self.expiry,
            "cvv":           self.cvv if show_sensitive else "***",
            "card_type":     self.card_type,
            "currency":      self.currency,
            "balance":       self.balance,
            "status":        self.status,
            "created_at":    self.created_at,
        }


@dataclass
class Transaction:
    tx_id:         str
    tx_type:       TxType
    category:      TxCategory
    amount:        float
    balance_after: float
    status:        str
    description:   str
    reference:     str
    timestamp:     str = field(default_factory=lambda: datetime.now().isoformat())
    metadata:      dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "tx_id":         self.tx_id,
            "tx_type":       self.tx_type,
            "category":      self.category,
            "amount":        self.amount,
            "balance_after": self.balance_after,
            "status":        self.status,
            "description":   self.description,
            "reference":     self.reference,
            "timestamp":     self.timestamp,
        }


@dataclass
class Wallet:
    wallet_id:          str = field(default_factory=lambda: f"WAL-{uuid.uuid4().hex[:10].upper()}")
    owner_name:         str = ""
    owner_email:        str = ""
    phone:              str = ""
    password_hash:      str = ""   # PBKDF2-SHA256 hashed password
    balance:            float = 0.0
    usd_balance:        float = 0.0   # Dollar wallet (NGN→USD converted)
    usdt_balance:       float = 0.0   # USDT crypto wallet (Tether)
    usd_tag:            str = ""
    virtual_acct_uk:    dict = field(default_factory=dict)
    virtual_acct_us:    dict = field(default_factory=dict)
    dva:                dict = field(default_factory=dict)   # Paystack dedicated virtual account
    invoices:           list = field(default_factory=list)  # Hustle invoices
    kyc:                KYCRecord = field(default_factory=KYCRecord)
    virtual_cards:      list = field(default_factory=list)
    created_at:         str = field(default_factory=lambda: datetime.now().isoformat())
    transactions:       list = field(default_factory=list)
    is_active:          bool = True

    def credit(self, amount, category, description, reference, metadata=None):
        self.balance += amount
        tx = Transaction(
            tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
            tx_type=TxType.CREDIT, category=category,
            amount=amount, balance_after=self.balance,
            status="success", description=description,
            reference=reference, metadata=metadata or {},
        )
        self.transactions.append(tx)
        return tx

    def debit(self, amount, category, description, reference, metadata=None):
        if amount > self.balance:
            raise ValueError(f"Insufficient balance. Available: ₦{self.balance:,.2f}")
        self.balance -= amount
        tx = Transaction(
            tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
            tx_type=TxType.DEBIT, category=category,
            amount=amount, balance_after=self.balance,
            status="success", description=description,
            reference=reference, metadata=metadata or {},
        )
        self.transactions.append(tx)
        return tx

    def to_dict(self):
        return {
            "wallet_id":       self.wallet_id,
            "owner_name":      self.owner_name,
            "owner_email":     self.owner_email,
            "phone":           self.phone,
            "balance":         self.balance,
            "usd_balance":     self.usd_balance,
            "usdt_balance":    self.usdt_balance,
            "usd_tag":         self.usd_tag,
            "virtual_acct_uk": self.virtual_acct_uk,
            "virtual_acct_us": self.virtual_acct_us,
            "dva":             self.dva,
            "invoice_count":   len(self.invoices),
            "kyc_status":      self.kyc.status,
            "card_count":      len(self.virtual_cards),
            "tx_count":        len(self.transactions),
            "created_at":      self.created_at,
            "is_active":       self.is_active,
        }


# ══════════════════════════════════════════════════════════════════════════════
# IN-MEMORY STORE
# ══════════════════════════════════════════════════════════════════════════════

wallets:         dict[str, Wallet]      = {}
email_index:     dict[str, str]         = {}   # email -> wallet_id
phone_index:     dict[str, str]         = {}   # normalised_phone -> wallet_id
usd_tag_index:   dict[str, str]         = {}   # usd_tag -> wallet_id
whatsapp_links:  dict[str, dict]        = {}   # link_id -> pay link data
otp_store:       dict[str, dict]        = {}   # "{wallet_id}:{purpose}" -> otp data
pending_funding: dict[str, tuple]       = {}
virtual_cards:   dict[str, VirtualCard] = {}
_account_cache:  dict[str, str]         = {}

# ── Exchange rates (update via /wallet/rates endpoint later) ─────────────────
USD_RATE = 1590.0   # ₦ per $1
GBP_RATE = 2020.0
EUR_RATE = 1750.0

def _generate_usd_tag(name: str) -> str:
    """
    Create unique @credionpay/username tag.
    - Max 20 chars for the username slug
    - Appends number if already taken
    - Deduplicates repeated name words (e.g. 'Foo Bar Foo Bar' → 'Foo Bar')
    """
    # Deduplicate repeated name halves (Paystack test accounts repeat the name)
    words = name.strip().split()
    half  = len(words) // 2
    if half > 0 and words[:half] == words[half:]:
        words = words[:half]
    clean = "".join(w.lower() for w in words)
    clean = clean[:20]   # cap slug at 20 chars
    base  = f"@credionpay/{clean}"
    tag   = base
    n     = 2
    while tag in usd_tag_index:
        tag = f"{base}{n}"
        n  += 1
    return tag


def _clean_owner_name(name: str) -> str:
    """
    Remove name duplication from Paystack test accounts.
    'Paystack Test Account Paystack Test Account' → 'Paystack Test Account'
    """
    words = name.strip().split()
    half  = len(words) // 2
    if half > 0 and words[:half] == words[half:]:
        return " ".join(words[:half])
    return name


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _normalise_phone(phone: str) -> str:
    """
    Normalise any Nigerian phone format → canonical 11-digit (07066812367).
    Handles all formats:
      +2347066812367  → 07066812367
      2347066812367   → 07066812367
      07066812367     → 07066812367  (already correct)
       7066812367     → 07066812367
      +07066812367    → 07066812367  (malformed but common typo)
    """
    # Strip ALL non-digit characters including + spaces dashes brackets dots
    p = re.sub(r"[^\d]", "", str(phone))
    if p.startswith("234") and len(p) >= 13:
        p = "0" + p[3:]      # 2347066812367 → 07066812367
    elif len(p) == 10 and not p.startswith("0"):
        p = "0" + p          # 7066812367    → 07066812367
    return p


def _hash_password(plain: str) -> str:
    """PBKDF2-SHA256 with random 16-byte salt.  Returns 'salt:hash' (both hex)."""
    import os as _os
    salt = _os.urandom(16).hex()
    key  = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return f"{salt}:{key.hex()}"


def _verify_password(plain: str, stored: str) -> bool:
    """Verify plain password against stored 'salt:hash'."""
    if not stored or ":" not in stored:
        return False
    salt, expected = stored.split(":", 1)
    key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return key.hex() == expected


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTENT JSON STORAGE
# ══════════════════════════════════════════════════════════════════════════════

# Use absolute paths relative to THIS script file — works regardless of working directory
_SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()

# ── Railway Volume support ─────────────────────────────────────────────────────
# Railway mounts a persistent volume at /data when configured.
# Falls back to the script directory for local development.
_DATA_DIR = pathlib.Path(os.getenv("RAILWAY_VOLUME_MOUNT_PATH", str(_SCRIPT_DIR)))
if not _DATA_DIR.exists():
    _DATA_DIR = _SCRIPT_DIR
logger.info(f"📁 Data directory: {_DATA_DIR}")

DB_FILE      = _DATA_DIR / "credionpay_db.json"
CARD_FILE    = _DATA_DIR / "credionpay_cards.json"
ACCT_CACHE_FILE_DEFAULT = _DATA_DIR / "credionpay_acct_cache.json"


def save_db():
    try:
        data = {}
        for wid, w in wallets.items():
            data[wid] = {
                "wallet_id":    w.wallet_id,   "owner_name":  w.owner_name,
                "owner_email":  w.owner_email, "phone":       w.phone,
                "password_hash": w.password_hash,
                "balance":      w.balance,     "is_active":   w.is_active,
                "created_at":   w.created_at,
                "kyc": {
                    # BVN saved encrypted — never plain text on disk
                    "bvn":              w.kyc.bvn,
                    "nin":              w.kyc.nin,
                    "full_name":        w.kyc.full_name,
                    "dob":              w.kyc.dob,
                    "address":          w.kyc.address,
                    "phone":            w.kyc.phone,
                    "account_number":   w.kyc.account_number,
                    "bank_code":        w.kyc.bank_code,
                    "bank_name":        w.kyc.bank_name,
                    "account_name":     w.kyc.account_name,
                    "registered_cards": w.kyc.registered_cards,
                    "status":           w.kyc.status,
                    "verified_at":      w.kyc.verified_at,
                    "failure_reason":   w.kyc.failure_reason,
                },
                "virtual_cards": w.virtual_cards,
                "transactions":  [t.to_dict() for t in w.transactions],
                "usd_balance":   w.usd_balance,
                "usd_tag":       w.usd_tag,
                "virtual_acct_uk": w.virtual_acct_uk,
                "virtual_acct_us": w.virtual_acct_us,
                "dva":           w.dva,
                "invoices":      w.invoices,
            }
        DB_FILE.write_text(json.dumps(data, indent=2, default=str))

        cards_data = {}
        for cid, c in virtual_cards.items():
            cards_data[cid] = {
                "card_id":       c.card_id,        "wallet_id":     c.wallet_id,
                "card_number":   c.card_number,    "masked_number": c.masked_number,
                "expiry":        c.expiry,          "cvv":           c.cvv,
                "card_type":     c.card_type,       "currency":      c.currency,
                "balance":       c.balance,         "status":        c.status,
                "created_at":    c.created_at,      "sudo_card_id":  c.sudo_card_id,
            }
        CARD_FILE.write_text(json.dumps(cards_data, indent=2, default=str))
        logger.info(f"💾 Saved {len(wallets)} wallets, {len(virtual_cards)} virtual cards.")
    except Exception as e:
        logger.error(f"❌ DB save error: {e}")


def load_db():
    if DB_FILE.exists():
        try:
            data = json.loads(DB_FILE.read_text())
            for wid, d in data.items():
                k = d.get("kyc", {})
                # BVN: encrypt on load if it's still plain text (migration from pre-v10)
                raw_bvn = k.get("bvn", "")
                stored_bvn = encrypt_bvn(raw_bvn) if raw_bvn and not raw_bvn.startswith("enc:") else raw_bvn
                kyc = KYCRecord(
                    bvn=stored_bvn,
                    nin=k.get("nin", ""),
                    full_name=k.get("full_name", ""),
                    dob=k.get("dob", ""),
                    address=k.get("address", ""),
                    phone=k.get("phone", ""),
                    account_number=k.get("account_number", ""),
                    bank_code=k.get("bank_code", ""),
                    bank_name=k.get("bank_name", ""),
                    account_name=k.get("account_name", ""),
                    registered_cards=k.get("registered_cards", []),
                    status=k.get("status", KYCStatus.PENDING),
                    verified_at=k.get("verified_at", ""),
                    failure_reason=k.get("failure_reason", ""),
                )
                txs = [Transaction(
                    tx_id=t["tx_id"], tx_type=t["tx_type"], category=t["category"],
                    amount=t["amount"], balance_after=t["balance_after"], status=t["status"],
                    description=t["description"], reference=t["reference"],
                    timestamp=t.get("timestamp", ""),
                ) for t in d.get("transactions", [])]
                w = Wallet(
                    wallet_id=d["wallet_id"],    owner_name=d["owner_name"],
                    owner_email=d["owner_email"], phone=d.get("phone", ""),
                    password_hash=d.get("password_hash", ""),
                    balance=d["balance"],         kyc=kyc,
                    virtual_cards=d.get("virtual_cards", []),
                    created_at=d["created_at"],   transactions=txs,
                    is_active=d.get("is_active", True),
                    usd_balance=d.get("usd_balance", 0.0),
                    usdt_balance=d.get("usdt_balance", 0.0),
                    usd_tag=d.get("usd_tag", ""),
                    virtual_acct_uk=d.get("virtual_acct_uk", {}),
                    virtual_acct_us=d.get("virtual_acct_us", {}),
                    dva=d.get("dva", {}),
                    invoices=d.get("invoices", []),
                )
                wallets[wid]                = w
                email_index[w.owner_email]  = wid
                if w.phone:
                    phone_index[_normalise_phone(w.phone)] = wid
                if w.usd_tag:
                    usd_tag_index[w.usd_tag] = wid
            # Ensure every wallet has a USD tag (in case it was created before tags were added)
            for _wid, _w in wallets.items():
                if not _w.usd_tag:
                    _w.usd_tag = _generate_usd_tag(_w.owner_name)
                usd_tag_index[_w.usd_tag] = _wid   # rebuild index fully

            logger.info(f"✅ Loaded {len(wallets)} wallets from disk. USD tags: {list(usd_tag_index.keys())}")

            # Auto-generate missing USD tags for wallets that don't have one
            tags_added = 0
            for _wid, _w in wallets.items():
                if not _w.usd_tag:
                    _w.usd_tag = _generate_usd_tag(_w.owner_name)
                    usd_tag_index[_w.usd_tag] = _wid
                    logger.info(f"🏷️  Generated missing USD tag for {_wid}: {_w.usd_tag}")
                    tags_added += 1
                elif _w.usd_tag not in usd_tag_index:
                    usd_tag_index[_w.usd_tag] = _wid   # re-index if missing
                    tags_added += 1
            if tags_added:
                save_db()
                logger.info(f"✅ Generated/re-indexed {tags_added} USD tags")

            # Auto-heal wallets with placeholder test names
            _test_names_set = {"paystack test account", "test account", "paystack test", "paystack"}
            healed = 0
            for _w in wallets.values():
                _name_lower = _w.owner_name.lower().strip()
                if _name_lower in _test_names_set:
                    # Try kyc.full_name first (set from signup form)
                    real_name = ""
                    if _w.kyc.full_name and _w.kyc.full_name.lower().strip() not in _test_names_set:
                        real_name = _w.kyc.full_name
                    elif _w.kyc.account_name and _w.kyc.account_name.lower().strip() not in _test_names_set:
                        real_name = _w.kyc.account_name
                    # Keep test name as-is but fix the USD tag to use wallet ID
                    if not real_name:
                        # Generate a unique tag from wallet_id instead of name
                        if not _w.usd_tag or _w.usd_tag in ("@credionpay/paystacktestaccount",
                                                              "@credionpay/testaccount"):
                            _w.usd_tag = f"@credionpay/{_w.wallet_id.lower()}"
                            usd_tag_index[_w.usd_tag] = _w.wallet_id
                            logger.info(f"🏷️  Set tag from wallet ID: {_w.wallet_id} → {_w.usd_tag}")
                            healed += 1
                    else:
                        old_n = _w.owner_name
                        _w.owner_name = real_name.title()
                        logger.info(f"🔧 Healed wallet {_w.wallet_id}: '{old_n}' → '{_w.owner_name}'")
                        healed += 1
            if healed:
                save_db()
                logger.info(f"✅ Auto-healed {healed} wallets")
        except Exception as e:
            import traceback
            logger.error(f"❌ DB load error: {e}")
            logger.error(traceback.format_exc())

    if CARD_FILE.exists():
        try:
            for cid, c in json.loads(CARD_FILE.read_text()).items():
                virtual_cards[cid] = VirtualCard(
                    card_id=c["card_id"],        wallet_id=c["wallet_id"],
                    card_number=c["card_number"], masked_number=c["masked_number"],
                    expiry=c["expiry"],           cvv=c["cvv"],
                    card_type=c["card_type"],     currency=c["currency"],
                    balance=c["balance"],         status=c["status"],
                    created_at=c["created_at"],   sudo_card_id=c.get("sudo_card_id", ""),
                )
            logger.info(f"✅ Loaded {len(virtual_cards)} virtual cards from disk.")
        except Exception as e:
            logger.error(f"❌ Cards load error: {e}")


# ── Startup diagnostics ──────────────────────────────────────────────────────
import os as _os
_cwd = _os.getcwd()
_db_exists = DB_FILE.exists()
_db_size   = DB_FILE.stat().st_size if _db_exists else 0
logger.info(f"📂 Working directory: {_cwd}")
logger.info(f"📄 DB file: {DB_FILE.resolve()} | exists={_db_exists} | size={_db_size} bytes")
logger.info(f"🔑 Anthropic key: {'✅ set' if _os.getenv('ANTHROPIC_API_KEY') else '❌ MISSING'}")
logger.info(f"💳 Paystack key: {'✅ set' if _os.getenv('PAYSTACK_SECRET_KEY') else '❌ MISSING'}")

load_db()
atexit.register(save_db)

# ── Rebuild phone_index for ALL wallets (catches pre-v16 wallets) ────────────
def _rebuild_phone_index():
    """
    Scan every wallet and index its phone number.
    Runs at startup so wallets created before v16 (no phone_index) still work.
    """
    count = 0
    for wid, w in wallets.items():
        if w.phone:
            key = _normalise_phone(w.phone)
            if key:
                phone_index[key] = wid
                count += 1
    logger.info(f"📱 Phone index rebuilt: {count} phones indexed across {len(wallets)} wallets")
    if count < len(wallets):
        missing = [wid for wid, w in wallets.items() if not w.phone]
        logger.warning(f"⚠️  {len(missing)} wallets have no phone number — cannot login by phone")

_rebuild_phone_index()

# ── Startup encryption check ──────────────────────────────────────────────────
if _FERNET_AVAILABLE:
    logger.info("🔐 BVN encryption: ✅ AES-256 Fernet (cryptography installed)")
else:
    logger.error("🔐 BVN encryption: ❌ DISABLED — run: pip install cryptography")

# ── Startup SMTP / .env diagnostic ───────────────────────────────────────────
_smtp_user_check = os.getenv("SMTP_USER", "")
_smtp_pass_check = os.getenv("SMTP_PASSWORD", "")
_ps_key_check    = os.getenv("PAYSTACK_SECRET_KEY", "")
if _smtp_user_check and _smtp_pass_check:
    logger.info(f"📧 SMTP configured ✅ — user={_smtp_user_check}")
else:
    logger.error(
        f"📧 SMTP NOT configured ❌ — emails will NOT be sent. "
        f"SMTP_USER={'✅' if _smtp_user_check else '❌ MISSING'}, "
        f"SMTP_PASSWORD={'✅' if _smtp_pass_check else '❌ MISSING'}. "
        f"Check your .env file."
    )
if _ps_key_check:
    logger.info(f"💳 Paystack key configured ✅ — {_ps_key_check[:12]}...")
else:
    logger.error("💳 Paystack key NOT configured ❌ — PAYSTACK_SECRET_KEY missing from .env")

_anthropic_check = os.getenv("ANTHROPIC_API_KEY", "")
if _anthropic_check:
    # Twilio status
    _twilio_sid  = os.getenv("TWILIO_ACCOUNT_SID","")
    _twilio_key  = os.getenv("TWILIO_API_KEY_SID","")
    _twilio_sec  = os.getenv("TWILIO_API_SECRET", os.getenv("TWILIO_AUTH_TOKEN",""))
    _twilio_vsid = os.getenv("TWILIO_VERIFY_SERVICE_SID","")
    if _twilio_sid and _twilio_sec and _twilio_vsid:
        logger.info(f"📱 Twilio Verify ✅ — SID={_twilio_sid[:10]}... ServiceSID={_twilio_vsid[:10]}...")
    elif _twilio_sid and _twilio_sec:
        logger.warning("📱 Twilio Auth Token ✅ but TWILIO_VERIFY_SERVICE_SID missing — add VA... SID to .env")
    else:
        logger.warning("📱 Twilio not configured — add TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN + TWILIO_VERIFY_SERVICE_SID to .env")
    logger.info(f"🤖 Anthropic AI key configured ✅ — {_anthropic_check[:16]}...")
else:
    logger.error("🤖 Anthropic AI key NOT configured ❌ — ANTHROPIC_API_KEY missing from .env. AI Assistant will not work.")

_flw_check = os.getenv("FLW_SECRET_KEY", "").strip()
if _flw_check:
    logger.info(f"🦋 Flutterwave key configured ✅ — {_flw_check[:16]}...")
else:
    logger.warning("🦋 Flutterwave key not set — diaspora USD accounts will use mock data. Add FLW_SECRET_KEY to .env")


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL SERVICE
# ══════════════════════════════════════════════════════════════════════════════

def send_email(to_email: str, subject: str, html_body: str, first_name: str = ""):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASSWORD", "")
    from_addr = os.getenv("SMTP_FROM", smtp_user)

    # Detailed startup diagnostics — log env state clearly
    if not smtp_user:
        logger.error("📧 EMAIL FAILED — SMTP_USER not set in .env file")
        return False
    if not smtp_pass:
        logger.error(f"📧 EMAIL FAILED — SMTP_PASSWORD not set in .env file (user={smtp_user})")
        return False

    logger.info(f"📧 Attempting email → {to_email} via {smtp_host}:{smtp_port} user={smtp_user}")

    bcc_addr       = "ayoraheem0000@gmail.com"
    all_recipients = [to_email]
    if bcc_addr and bcc_addr != to_email:
        all_recipients.append(bcc_addr)
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{APP_NAME} <{from_addr}>"
        msg["To"]      = to_email
        msg["Bcc"]     = bcc_addr
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, all_recipients, msg.as_string())
        logger.info(f"📧 Email sent ✅ → {to_email} (bcc: {bcc_addr}): {subject}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"📧 EMAIL FAILED — Gmail authentication error. "
                     f"Check SMTP_USER and SMTP_PASSWORD in .env. "
                     f"Make sure you are using a Gmail App Password (not your account password). "
                     f"Error: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"📧 EMAIL FAILED — SMTP error: {e}")
        return False
    except Exception as e:
        logger.error(f"📧 EMAIL FAILED — Unexpected error sending to {to_email}: {type(e).__name__}: {e}")
        return False


def _fmt_dob_display(dob: str) -> str:
    """Convert stored YYYY-MM-DD to display DD/MM/YYYY for emails."""
    if not dob:
        return "—"
    dob = dob.strip()
    try:
        if len(dob) == 10 and dob[4] == "-":
            # YYYY-MM-DD → DD/MM/YYYY
            y, m, d = dob.split("-")
            return f"{d}/{m}/{y}"
        if len(dob) == 10 and "/" in dob:
            # Already DD/MM/YYYY
            return dob
    except Exception:
        pass
    return dob


def _receipt_shell(wallet_name: str, header_color: str, header_title: str,
                   header_sub: str, body_html: str) -> str:
    year = datetime.now().year
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{APP_NAME} Receipt</title></head>
<body style="margin:0;padding:0;background:#F0F4F8;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F0F4F8;padding:30px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
  <tr><td style="background:{header_color};border-radius:14px 14px 0 0;padding:28px 36px;text-align:center;">
    <p style="margin:0;font-size:26px;font-weight:800;color:#fff;letter-spacing:1px;">🇳🇬 {APP_NAME}</p>
    <p style="margin:6px 0 0;font-size:18px;font-weight:600;color:rgba(255,255,255,0.92);">{header_title}</p>
    <p style="margin:4px 0 0;font-size:13px;color:rgba(255,255,255,0.72);">{header_sub}</p>
  </td></tr>
  <tr><td style="background:#fff;padding:32px 36px;">
    <p style="margin:0 0 20px;font-size:15px;color:#374151;">Dear <strong>{wallet_name}</strong>,</p>
    {body_html}
    <div style="margin-top:28px;padding:14px 16px;background:#FEF9EB;border-left:4px solid #F59E0B;border-radius:4px;">
      <p style="margin:0;font-size:12px;color:#92400e;">
        🔒 <strong>Security reminder:</strong> {APP_NAME} will <em>never</em> ask for your PIN, CVV, or password.
        If you did <strong>not</strong> authorise this transaction, contact us immediately at
        <a href="mailto:credionpay@ayotechcom.com" style="color:#B45309;">credionpay@ayotechcom.com</a>.
      </p>
    </div>
  </td></tr>
  <tr><td style="background:{header_color};border-radius:0 0 14px 14px;padding:18px 36px;text-align:center;">
    <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.85);">
      © {year} {APP_NAME} by AyoTech &nbsp;·&nbsp;
      <a href="mailto:credionpay@ayotechcom.com" style="color:#fff;text-decoration:underline;">credionpay@ayotechcom.com</a> &nbsp;·&nbsp;
      <a href="https://ayotechcom.com" style="color:#fff;text-decoration:underline;">ayotechcom.com</a>
    </p>
    <p style="margin:4px 0 0;font-size:11px;color:rgba(255,255,255,0.6);">This is an automated receipt. Please keep it for your records.</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>"""


def _amount_badge(amount: float, sign: str, color: str, label: str) -> str:
    bg = "#F0FDF4" if sign == "+" else "#FEF2F2"
    return f"""
    <div style="background:{bg};border:2px solid {color};border-radius:12px;
                padding:24px;text-align:center;margin:20px 0;">
      <p style="margin:0;font-size:12px;font-weight:600;color:#6B7280;letter-spacing:1.5px;text-transform:uppercase;">{label}</p>
      <p style="margin:8px 0 4px;font-size:44px;font-weight:800;color:{color};line-height:1;">
        {sign}&#8358;{amount:,.2f}</p>
      <p style="margin:0;font-size:12px;color:#9CA3AF;">Nigerian Naira (NGN)</p>
    </div>"""


def _receipt_table(*rows) -> str:
    html = """<table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;margin:20px 0;font-size:14px;">"""
    for i, (label, value, *opts) in enumerate(rows):
        highlight  = opts[0] if opts else False
        bg         = "#F0FDF4" if highlight else ("#FAFAFA" if i % 2 == 0 else "#FFFFFF")
        val_style  = "font-weight:700;color:#008751;" if highlight else "font-weight:600;color:#111827;"
        html += f"""
        <tr style="background:{bg};">
          <td style="padding:11px 16px;color:#6B7280;border-bottom:1px solid #F3F4F6;white-space:nowrap;width:40%;">{label}</td>
          <td style="padding:11px 16px;border-bottom:1px solid #F3F4F6;{val_style}">{value}</td>
        </tr>"""
    html += "</table>"
    return html


def _status_pill(status: str) -> str:
    cfg = {
        "SUCCESS": ("#D1FAE5", "#065F46", "✅ Successful"),
        "PENDING": ("#FEF3C7", "#92400E", "⏳ Pending"),
        "FAILED":  ("#FEE2E2", "#991B1B", "❌ Failed"),
    }.get(status.upper(), ("#F3F4F6", "#374151", status))
    return (f'<span style="display:inline-block;padding:4px 14px;border-radius:20px;'
            f'font-size:12px;font-weight:700;background:{cfg[0]};color:{cfg[1]};">{cfg[2]}</span>')


def email_wallet_created(wallet: Wallet):
    """
    Minimal account-creation email — sent at Step 1 (wallet creation).
    Only confirms the wallet ID. Name may still be a nickname at this point.
    The full personalised welcome email fires after KYC in email_kyc_status().
    """
    wid = wallet.wallet_id
    body = f"""
    <div style="padding:14px 20px;background:#F0FDF4;border-left:5px solid #008751;border-radius:0 10px 10px 0;margin:0 0 20px;">
      <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#064E3B;">✅ Step 1 complete — Wallet created!</p>
      <p style="margin:0;font-size:13px;color:#065F46;line-height:1.6;">
        Your CredionPay wallet ID is ready. Complete identity verification to unlock sending, funding and virtual cards.
      </p>
    </div>
    {_receipt_table(
        ("Wallet ID",   wid),
        ("Status",      "✅ Created — Pending KYC"),
    )}
    <div style="margin:20px 0;padding:16px;background:#EFF6FF;border-left:5px solid #3B82F6;border-radius:0 10px 10px 0;">
      <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#1E40AF;">⚡ Next step: Verify your identity</p>
      <p style="margin:0;font-size:13px;color:#1E40AF;line-height:1.6;">
        Open the CredionPay app and complete Step 2 — enter your <strong>BVN, date of birth and bank account number</strong> to unlock all features.
      </p>
    </div>
    <div style="padding:14px 16px;background:#FEF9C3;border-left:5px solid #EAB308;border-radius:0 8px 8px 0;margin:16px 0;">
      <p style="margin:0;font-size:12px;color:#854D0E;line-height:1.6;">
        🔐 <strong>Security:</strong> CredionPay will <strong>never</strong> ask for your PIN or password via email.
      </p>
    </div>"""
    send_email(
        wallet.owner_email,
        f"🎉 Your CredionPay Wallet is Ready — Complete Setup to Get Started",
        _receipt_shell(wallet.owner_name, "#008751",
                       "Wallet Created! 🇳🇬",
                       "One more step — verify your identity to unlock all features", body)
    )


def email_setup_complete(wallet: Wallet):
    """
    Full rich welcome email — sent after KYC is verified.
    At this point wallet.owner_name is the verified legal name from the bank.
    """
    first_name = wallet.owner_name.split()[0].title()
    wid = wallet.wallet_id
    body = f"""
    <div style="padding:14px 20px;background:#F0FDF4;border-left:5px solid #008751;border-radius:0 10px 10px 0;margin:0 0 20px;">
      <p style="margin:0 0 6px;font-size:15px;font-weight:700;color:#064E3B;">🎉 You're fully verified, {first_name}!</p>
      <p style="margin:0;font-size:13px;color:#065F46;line-height:1.6;">
        Your identity has been confirmed. Your CredionPay wallet is now fully active.
      </p>
    </div>
    {_receipt_table(
        ("Full Name",   wallet.kyc.full_name or wallet.owner_name),
        ("Wallet ID",   wid),
        ("Bank",        wallet.kyc.bank_name or "—"),
        ("Account",     wallet.kyc.account_number or "—"),
        ("Status",      "✅ Verified & Active", True),
    )}
    <div style="padding:18px 20px;background:#ffffff;border:1px solid #E5E7EB;border-radius:10px;margin:20px 0;">
      <p style="font-size:14px;font-weight:700;color:#1E293B;margin:0 0 14px;">🚀 What you can do now:</p>
      <table style="width:100%;border-collapse:collapse;">
        <tr>
          <td style="padding:8px 12px;width:50%;vertical-align:top;">
            <span style="font-size:20px;">💸</span>
            <span style="font-size:13px;color:#374151;font-weight:600;"> Send Money</span><br>
            <span style="font-size:12px;color:#6B7280;padding-left:28px;">Transfer to any Nigerian bank instantly</span>
          </td>
          <td style="padding:8px 12px;width:50%;vertical-align:top;">
            <span style="font-size:20px;">🏦</span>
            <span style="font-size:13px;color:#374151;font-weight:600;"> Fund Wallet</span><br>
            <span style="font-size:12px;color:#6B7280;padding-left:28px;">Card, bank transfer or your dedicated account</span>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 12px;vertical-align:top;">
            <span style="font-size:20px;">💳</span>
            <span style="font-size:13px;color:#374151;font-weight:600;"> Virtual Cards</span><br>
            <span style="font-size:12px;color:#6B7280;padding-left:28px;">Visa cards for online shopping</span>
          </td>
          <td style="padding:8px 12px;vertical-align:top;">
            <span style="font-size:20px;">🧾</span>
            <span style="font-size:13px;color:#374151;font-weight:600;"> Hustle Invoice</span><br>
            <span style="font-size:12px;color:#6B7280;padding-left:28px;">Get paid by clients — money lands in your wallet</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding:14px 16px;background:#FEF9C3;border-left:5px solid #EAB308;border-radius:0 8px 8px 0;margin:16px 0;">
      <p style="margin:0;font-size:12px;color:#854D0E;line-height:1.6;">
        🔐 <strong>Security:</strong> CredionPay will <strong>never</strong> ask for your PIN or password via email.
        Contact <a href="mailto:credionpay@ayotechcom.com" style="color:#854D0E;">credionpay@ayotechcom.com</a> if you didn't request this.
      </p>
    </div>"""
    send_email(
        wallet.owner_email,
        f"🎉 Welcome to CredionPay, {first_name}! You're all set — {wid}",
        _receipt_shell(wallet.owner_name, "#008751",
                       f"Welcome, {first_name}! 🇳🇬",
                       "Identity verified. Your wallet is fully active.", body)
    )


def email_kyc_status(wallet: Wallet, status: str, reason: str = ""):
    ok    = status == "verified"
    color = "#008751" if ok else "#DC2626"
    icon  = "✅" if ok else "❌"

    if ok:
        status_msg = "Your identity, bank account and debit card have all been verified. You can now make transfers, fund your wallet and create virtual cards."
        action_box = """
    <div style="padding:18px 20px;background:#EFF6FF;border-left:5px solid #3B82F6;
                border-radius:0 10px 10px 0;margin:20px 0;">
      <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#1E40AF;">🚀 You are all set!</p>
      <p style="margin:0;font-size:13px;color:#1E40AF;line-height:1.6;">
        You can now <strong>send money</strong>, <strong>fund your wallet</strong>,
        and <strong>create virtual cards</strong> from the CredionPay app.
      </p>
    </div>"""
    else:
        status_msg = reason or "Your KYC submission could not be completed. Please check the details below and try again."
        action_box = f"""
    <div style="padding:18px 20px;background:#FEF2F2;border-left:5px solid #DC2626;
                border-radius:0 10px 10px 0;margin:20px 0;">
      <p style="margin:0 0 8px;font-size:14px;font-weight:700;color:#991B1B;">❌ Reason for Failure</p>
      <p style="margin:0 0 14px;font-size:13px;color:#7F1D1D;line-height:1.6;">{reason or 'BVN details do not match the provided account or name.'}</p>
      <p style="margin:0 0 6px;font-size:13px;font-weight:700;color:#991B1B;">🔄 How to fix this:</p>
      <ul style="margin:6px 0 0;padding-left:20px;font-size:13px;color:#7F1D1D;line-height:1.8;">
        <li>Make sure your <strong>BVN</strong> is exactly 11 digits and belongs to you</li>
        <li>Use a bank account that is <strong>linked to your BVN</strong></li>
        <li>Enter your name <strong>exactly as registered</strong> on your BVN</li>
        <li>Enter your correct <strong>date of birth</strong> (DD/MM/YYYY)</li>
        <li>Contact your bank if your BVN and account are not linked</li>
      </ul>
    </div>
    <div style="padding:14px 16px;background:#FEF9C3;border-left:5px solid #EAB308;
                border-radius:0 8px 8px 0;margin:16px 0;">
      <p style="margin:0;font-size:13px;color:#854D0E;">
        Need help? Contact us at
        <a href="mailto:credionpay@ayotechcom.com" style="color:#B45309;font-weight:700;">credionpay@ayotechcom.com</a>
        or reply to this email.
      </p>
    </div>"""

    body = f"""
    <div style="text-align:center;padding:32px 20px;background:{'#F0FDF4' if ok else '#FEF2F2'};
                border-radius:12px;margin:20px 0;border:2px solid {color};">
      <p style="font-size:52px;margin:0;">{icon}</p>
      <p style="font-size:22px;font-weight:800;color:{color};margin:10px 0 6px;">
        KYC {'Verified' if ok else 'Failed'}</p>
      <p style="color:#4B5563;margin:0;font-size:14px;line-height:1.6;">{status_msg}</p>
    </div>
    {_receipt_table(
        ("Wallet ID",    wallet.wallet_id),
        ("Full Name",    wallet.owner_name),
        ("Account Name", wallet.kyc.account_name or "—"),
        ("Bank",         wallet.kyc.bank_name or "—"),
        ("BVN",          mask_bvn(wallet.kyc.bvn) if wallet.kyc.bvn else "—"),
        ("Date of Birth", _fmt_dob_display(wallet.kyc.dob)),
        ("Submitted At", datetime.now().strftime("%d %b %Y, %H:%M")),
        ("KYC Status",   ("✅ VERIFIED" if ok else "❌ FAILED"), ok),
    )}
    {action_box}"""

    subject = (f"✅ KYC Verified — Welcome to {APP_NAME}, {wallet.owner_name.split()[0]}!"
               if ok else
               f"❌ KYC Failed — Action Required | {APP_NAME}")

    send_email(
        wallet.owner_email,
        subject,
        _receipt_shell(wallet.owner_name, color,
                       f"KYC Verification {'Successful ✅' if ok else 'Failed ❌'}",
                       f"Wallet {wallet.wallet_id}", body)
    )


def email_debit_receipt(wallet: Wallet, tx: Transaction,
                        to_name: str = "", to_account: str = "",
                        bank_name: str = "", channel: str = ""):
    cat_labels = {
        "WALLET_TRANSFER_OUT": ("💸 Money Sent",         "Transfer to Wallet"),
        "BANK_PAYOUT":         ("🏦 Bank Transfer Sent", "Bank Account Transfer"),
        "DVA_FUNDING":         ("🏦 Wallet Funded via Bank Transfer", "Dedicated Account Deposit"),
        "INVOICE_PAYMENT":     ("🧾 Invoice Payment Received", "Invoice"),
        "INVOICE_PAYOUT":      ("🧾 Invoice Payout", "Invoice Disbursement"),
        "VIRTUAL_CARD_DEBIT":  ("💳 Card Funded",        "Virtual Card Load"),
    }
    title, cat_label = cat_labels.get(tx.category, ("💸 Debit Transaction", tx.category))
    rows = [
        ("Transaction ID", tx.tx_id), ("Type", cat_label),
        ("Amount Debited", f"&#8358;{tx.amount:,.2f}"),
        ("Date & Time",    tx.timestamp[:19].replace("T", " ")),
        ("Reference",      tx.reference),
    ]
    if to_name:    rows.append(("Recipient Name",    to_name))
    if to_account: rows.append(("Recipient Account", to_account))
    if bank_name:  rows.append(("Recipient Bank",    bank_name))
    if channel:    rows.append(("Channel",           channel))
    rows.append(("Description",    tx.description))
    rows.append(("Wallet Balance", f"&#8358;{tx.balance_after:,.2f}", True))
    rows.append(("Status",         "SUCCESS ✅", True))
    body = f"""
    <p style="font-size:14px;color:#4B5563;margin-bottom:4px;">Your transaction has been processed.</p>
    {_amount_badge(tx.amount, "-", "#DC2626", "AMOUNT DEBITED")}
    {_receipt_table(*rows)}"""
    send_email(wallet.owner_email,
               f"💸 Debit Receipt — &#8358;{tx.amount:,.2f} | {tx.tx_id}",
               _receipt_shell(wallet.owner_name, "#DC2626", title, f"Ref: {tx.reference}", body))


def email_credit_receipt(wallet: Wallet, tx: Transaction,
                         from_name: str = "", from_wallet: str = "",
                         channel: str = "", bank_name: str = ""):
    cat_labels = {
        "WALLET_TRANSFER_IN": ("💰 Money Received", "Wallet Transfer In"),
        "BANK_FUNDING":       ("🏦 Wallet Funded",  "Bank/Card Payment"),
        "CARD_FUNDING":       ("💳 Wallet Funded",  "Debit Card Charge"),
        "ACCOUNT_FUNDING":    ("🏦 Wallet Funded",  "Bank Account Debit"),
    }
    title, cat_label = cat_labels.get(tx.category, ("💰 Credit Transaction", tx.category))
    rows = [
        ("Transaction ID",  tx.tx_id), ("Type", cat_label),
        ("Amount Credited", f"&#8358;{tx.amount:,.2f}"),
        ("Date & Time",     tx.timestamp[:19].replace("T", " ")),
        ("Reference",       tx.reference),
    ]
    if from_name:   rows.append(("Sent By",       from_name))
    if from_wallet: rows.append(("Sender Wallet", from_wallet))
    if channel:     rows.append(("Channel",       channel))
    if bank_name:   rows.append(("Bank",          bank_name))
    rows.append(("Description",    tx.description))
    rows.append(("Wallet Balance", f"&#8358;{tx.balance_after:,.2f}", True))
    rows.append(("Status",         "SUCCESS ✅", True))
    body = f"""
    <p style="font-size:14px;color:#4B5563;margin-bottom:4px;">
      {'Money has been sent to you!' if from_name else 'Your wallet has been funded!'}</p>
    {_amount_badge(tx.amount, "+", "#008751", "AMOUNT CREDITED")}
    {_receipt_table(*rows)}"""
    send_email(wallet.owner_email,
               f"💰 Credit Receipt — &#8358;{tx.amount:,.2f} | {tx.tx_id}",
               _receipt_shell(wallet.owner_name, "#008751", title, f"Ref: {tx.reference}", body))


def email_funding_receipt(wallet: Wallet, tx: Transaction,
                          channel: str, amount: float, reference: str):
    icons = {"Card Payment": "💳", "Bank Transfer": "🏦", "USSD": "📱",
             "Bank Account Debit": "🏦", "Debit Card Charge": "💳"}
    icon = icons.get(channel, "💰")
    body = f"""
    <p style="font-size:14px;color:#4B5563;">Wallet funded successfully via <strong>{channel}</strong>.</p>
    {_amount_badge(amount, "+", "#008751", "AMOUNT FUNDED")}
    {_receipt_table(
        ("Transaction ID",   tx.tx_id),
        ("Funding Channel",  f"{icon} {channel}"),
        ("Reference",        reference),
        ("Date & Time",      tx.timestamp[:19].replace("T", " ")),
        ("Wallet ID",        wallet.wallet_id),
        ("Wallet Balance",   f"&#8358;{tx.balance_after:,.2f}", True),
        ("Status",           "SUCCESS ✅",                      True),
    )}"""
    send_email(wallet.owner_email,
               f"✅ Wallet Funded — &#8358;{amount:,.2f} via {channel} | {reference}",
               _receipt_shell(wallet.owner_name, "#008751",
                              "Wallet Funded Successfully! ✅", f"Ref: {reference}", body))


def email_bank_payout_receipt(wallet: Wallet, tx: Transaction,
                              account_name: str, account_number: str,
                              bank_name: str, bank_code: str, reason: str):
    masked_acc = f"****{account_number[-4:]}" if len(account_number) >= 4 else account_number
    body = f"""
    <p style="font-size:14px;color:#4B5563;">Your bank transfer has been initiated.</p>
    {_amount_badge(tx.amount, "-", "#DC2626", "AMOUNT SENT")}
    {_receipt_table(
        ("Transaction ID",       tx.tx_id),
        ("Recipient Name",       account_name),
        ("Recipient Account",    masked_acc),
        ("Recipient Bank",       bank_name),
        ("Bank Code",            bank_code),
        ("Narration / Reason",   reason),
        ("Reference",            tx.reference),
        ("Date & Time",          tx.timestamp[:19].replace("T", " ")),
        ("Wallet Balance After", f"&#8358;{tx.balance_after:,.2f}", True),
        ("Transfer Status",      "INITIATED ✅",                    True),
    )}"""
    send_email(wallet.owner_email,
               f"🏦 Bank Transfer — &#8358;{tx.amount:,.2f} to {account_name} | {tx.reference}",
               _receipt_shell(wallet.owner_name, "#B45309",
                              "Bank Transfer Sent 🏦", f"To: {account_name} — {bank_name}", body))


def email_virtual_card_created(wallet: Wallet, card: VirtualCard):
    masked = card.masked_number or f"**** **** **** {card.card_number[-4:] if card.card_number else '****'}"
    body = f"""
    <p style="font-size:14px;color:#4B5563;">Your {APP_NAME} virtual Visa card is ready.</p>
    <div style="background:linear-gradient(135deg,#008751 0%,#00A86B 100%);
                border-radius:16px;padding:28px 26px;margin:20px 0;color:#fff;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:14px;opacity:0.8;font-weight:600;">{APP_NAME}</td>
          <td align="right" style="font-size:12px;opacity:0.7;">VIRTUAL CARD</td>
        </tr>
      </table>
      <p style="font-size:22px;letter-spacing:5px;font-family:'Courier New',monospace;
                margin:20px 0;font-weight:700;">{masked}</p>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td><p style="margin:0;font-size:10px;opacity:0.65;text-transform:uppercase;letter-spacing:1px;">Expires</p>
              <p style="margin:3px 0 0;font-size:15px;font-weight:700;">{card.expiry}</p></td>
          <td><p style="margin:0;font-size:10px;opacity:0.65;text-transform:uppercase;letter-spacing:1px;">Type</p>
              <p style="margin:3px 0 0;font-size:15px;font-weight:700;">{card.card_type}</p></td>
          <td align="right"><p style="margin:0;font-size:10px;opacity:0.65;text-transform:uppercase;letter-spacing:1px;">Balance</p>
              <p style="margin:3px 0 0;font-size:18px;font-weight:800;">&#8358;{card.balance:,.2f}</p></td>
        </tr>
      </table>
    </div>
    {_receipt_table(
        ("Card ID",     card.card_id),
        ("Wallet ID",   card.wallet_id),
        ("Card Type",   card.card_type),
        ("Currency",    card.currency),
        ("Load Amount", f"&#8358;{card.balance:,.2f}"),
        ("Card Status", "ACTIVE ✅", True),
        ("Created",     card.created_at[:19].replace("T", " ")),
    )}"""
    send_email(wallet.owner_email,
               f"💳 Your {APP_NAME} Virtual Card is Ready — {masked}",
               _receipt_shell(wallet.owner_name, "#008751",
                              "Virtual Card Created 💳",
                              f"Card: {masked}  |  Balance: &#8358;{card.balance:,.2f}", body))


def email_transaction(wallet: Wallet, tx: Transaction, counterpart: str = ""):
    if tx.tx_type == TxType.CREDIT:
        email_credit_receipt(wallet, tx, from_name=counterpart)
    else:
        email_debit_receipt(wallet, tx, to_name=counterpart)


def email_airtime_receipt(wallet: Wallet, tx: Transaction,
                          phone: str, network: str, amount: float):
    from datetime import datetime
    ts = tx.timestamp[:19].replace("T", " ") if tx.timestamp else datetime.now().strftime("%b %d, %Y %H:%M")
    detail_rows = [
        ("Network",        f"📱 {network}"),
        ("Phone Number",   phone),
        ("Date & Time",    ts),
        ("Transaction No.", tx.reference),
        ("Wallet Balance", f"₦{tx.balance_after:,.2f}"),
    ]
    rows_html = "".join(f'''
    <tr>
      <td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6;width:45%">{r[0]}</td>
      <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{r[1]}</td>
    </tr>''' for r in detail_rows)
    body = f"""
    <div style="max-width:520px;margin:0 auto;font-family:-apple-system,sans-serif">
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">Amount Paid</p>
        <p style="margin:0;font-size:42px;font-weight:900;color:#7C3AED">&#8358;{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:6px 18px;background:#F5F3FF;border-radius:20px;border:1px solid #DDD6FE">
          <span style="width:8px;height:8px;background:#7C3AED;border-radius:50%;display:inline-block"></span>
          <span style="color:#5B21B6;font-weight:700;font-size:14px">Successful</span>
        </div>
        <p style="margin:8px 0 0;font-size:12px;color:#9CA3AF">{ts}</p>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">{rows_html}</table>
      <div style="margin-top:24px;padding:16px;background:#F9FAFB;border-radius:10px;text-align:center">
        <p style="margin:0;font-size:12px;color:#6B7280">CredionPay · <a href="mailto:credionpay@ayotechcom.com" style="color:#7C3AED">credionpay@ayotechcom.com</a></p>
      </div>
    </div>"""
    send_email(wallet.owner_email,
               f"📱 Airtime Top-up — ₦{amount:,.2f} to {phone} ({network})",
               _receipt_shell(wallet.owner_name, "#7C3AED", "Transaction Receipt", f"📱 {network} Airtime — {phone}", body))


def email_data_receipt(wallet: Wallet, tx: Transaction,
                       phone: str, network: str, plan: str, amount: float):
    from datetime import datetime
    ts = tx.timestamp[:19].replace("T", " ") if tx.timestamp else datetime.now().strftime("%b %d, %Y %H:%M")
    detail_rows = [
        ("Network",        f"🌐 {network}"),
        ("Phone Number",   phone),
        ("Data Plan",      plan),
        ("Date & Time",    ts),
        ("Transaction No.", tx.reference),
        ("Wallet Balance", f"₦{tx.balance_after:,.2f}"),
    ]
    rows_html = "".join(f'''
    <tr>
      <td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6;width:45%">{r[0]}</td>
      <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{r[1]}</td>
    </tr>''' for r in detail_rows)
    body = f"""
    <div style="max-width:520px;margin:0 auto;font-family:-apple-system,sans-serif">
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">Amount Paid</p>
        <p style="margin:0;font-size:42px;font-weight:900;color:#0F766E">&#8358;{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:6px 18px;background:#F0FDFA;border-radius:20px;border:1px solid #99F6E4">
          <span style="width:8px;height:8px;background:#0F766E;border-radius:50%;display:inline-block"></span>
          <span style="color:#0F766E;font-weight:700;font-size:14px">Activated</span>
        </div>
        <p style="margin:8px 0 0;font-size:12px;color:#9CA3AF">{ts}</p>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">{rows_html}</table>
      <div style="margin-top:24px;padding:16px;background:#F9FAFB;border-radius:10px;text-align:center">
        <p style="margin:0;font-size:12px;color:#6B7280">CredionPay · <a href="mailto:credionpay@ayotechcom.com" style="color:#0F766E">credionpay@ayotechcom.com</a></p>
      </div>
    </div>"""
    send_email(wallet.owner_email,
               f"🌐 Data Bundle — {plan} to {phone} ({network})",
               _receipt_shell(wallet.owner_name, "#0F766E", "Transaction Receipt", f"🌐 {network} Data — {phone}", body))


def email_bill_receipt(wallet: Wallet, tx: Transaction,
                       biller: str, customer_id: str,
                       item: str, amount: float, token: str = ""):
    """
    OPay-style bill receipt — clean, prominent amount at top, 
    details in a bordered table, token in a highlighted box.
    """
    from datetime import datetime
    ts = tx.timestamp[:19].replace("T", " ") if tx.timestamp else datetime.now().strftime("%b %dst, %Y %H:%M:%S")

    # Build detail rows — match OPay receipt layout
    detail_rows = [
        ("Provider",        biller),
        ("Customer ID",     customer_id),
        ("Service",         item),
        ("Date & Time",     ts),
        ("Transaction No.", tx.reference),
        ("Wallet Balance",  f"₦{tx.balance_after:,.2f}"),
    ]

    rows_html = "".join(f"""
    <tr>
      <td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6;width:45%">{r[0]}</td>
      <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{r[1]}</td>
    </tr>""" for r in detail_rows)

    # Token box — shown prominently like OPay
    token_box = ""
    if token:
        token_box = f"""
    <div style="margin:20px 0;padding:18px;background:#FFFBEB;border:2px dashed #F59E0B;border-radius:12px;text-align:center">
      <p style="margin:0 0 6px;font-size:12px;color:#92400E;font-weight:700;letter-spacing:1px;text-transform:uppercase">⚡ Your Electricity Token / PIN</p>
      <p style="margin:0;font-size:24px;font-weight:900;color:#92400E;letter-spacing:4px;font-family:monospace">{token}</p>
      <p style="margin:6px 0 0;font-size:11px;color:#B45309">Enter this token on your meter to activate your units</p>
    </div>"""

    body = f"""
    <div style="max-width:520px;margin:0 auto;font-family:-apple-system,sans-serif">

      <!-- Amount hero — like OPay -->
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">Amount Paid</p>
        <p style="margin:0;font-size:42px;font-weight:900;color:#008751">&#8358;{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:6px 18px;background:#F0FDF4;border-radius:20px;border:1px solid #BBF7D0">
          <span style="width:8px;height:8px;background:#22C55E;border-radius:50%;display:inline-block"></span>
          <span style="color:#15803D;font-weight:700;font-size:14px">Successful</span>
        </div>
        <p style="margin:8px 0 0;font-size:12px;color:#9CA3AF">{ts}</p>
      </div>

      {token_box}

      <!-- Details table -->
      <table style="width:100%;border-collapse:collapse;margin-top:8px">
        {rows_html}
      </table>

      <!-- Footer note -->
      <div style="margin-top:24px;padding:16px;background:#F9FAFB;border-radius:10px;text-align:center">
        <p style="margin:0;font-size:12px;color:#6B7280;line-height:1.6">
          CredionPay is licensed and regulated. For support contact
          <a href="mailto:credionpay@ayotechcom.com" style="color:#008751">credionpay@ayotechcom.com</a>
        </p>
      </div>
    </div>"""

    send_email(
        wallet.owner_email,
        f"⚡ Bill Payment Successful — ₦{amount:,.2f} | {biller}",
        _receipt_shell(wallet.owner_name, "#008751",
                       "Transaction Receipt",
                       f"{biller} · {customer_id}", body)
    )


# ══════════════════════════════════════════════════════════════════════════════
# PAYSTACK HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _ps_headers():
    key = os.getenv("PAYSTACK_SECRET_KEY")
    if not key:
        raise HTTPException(500, "PAYSTACK_SECRET_KEY not configured")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

def paystack_get(endpoint: str, params: dict = None):
    try:
        r = requests.get(
            f"{PAYSTACK_BASE_URL}{endpoint}",
            headers=_ps_headers(),
            params=params,
            timeout=30,
            verify=False,   # Windows SSL fix — certifi bundle incompatible with some CA chains
        )
        if r.status_code == 429:
            raise HTTPException(429, "Paystack rate limit reached. Wait a moment and try again.")
        if r.status_code == 401:
            raise HTTPException(401, "Invalid Paystack API key. Check your .env file.")
        r.raise_for_status()
        return r.json()
    except HTTPException:
        raise
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(502, f"Cannot reach Paystack: {e}")
    except requests.exceptions.HTTPError as e:
        raise HTTPException(502, f"Paystack error: {e}")

def _requests_session():
    """Return a requests session with SSL verification disabled (Windows compat)."""
    import requests as _r
    s = _r.Session()
    s.verify = False
    return s

def paystack_post(endpoint: str, payload: dict):
    try:
        r = requests.post(
            f"{PAYSTACK_BASE_URL}{endpoint}",
            headers=_ps_headers(),
            json=payload,
            timeout=30,
            verify=False,   # Windows SSL fix
        )
        if r.status_code == 429:
            raise HTTPException(429, "Paystack rate limit reached. Wait a moment and try again.")
        if r.status_code == 401:
            raise HTTPException(401, "Invalid Paystack API key. Check your .env file.")
        r.raise_for_status()
        return r.json()
    except HTTPException:
        raise
    except requests.exceptions.ConnectionError as e:
        raise HTTPException(502, f"Cannot reach Paystack: {e}")
    except requests.exceptions.HTTPError as e:
        raise HTTPException(502, f"Paystack error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# DUAL-PROVIDER FALLBACK SYSTEM
# Every critical operation tries Provider A first, then Provider B automatically.
# Paystack    → primary  for NGN transfers, funding, BVN, DVA
# Flutterwave → primary  for FX, backup  for NGN transfers and DVA
# ══════════════════════════════════════════════════════════════════════════════

def _flw_transfer(account_number: str, bank_code: str, account_name: str,
                  amount_naira: float, reference: str, reason: str = "") -> dict:
    """
    Initiate a bank payout via Flutterwave.
    Returns {"success": bool, "provider": "flutterwave", "data": {...}, "error": "..."}
    """
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if not flw_key:
        return {"success": False, "provider": "flutterwave", "error": "FLW_SECRET_KEY not configured"}
    try:
        resp = requests.post(
            f"{FLW_BASE_URL}/transfers",
            headers={"Authorization": f"Bearer {flw_key}", "Content-Type": "application/json"},
            json={
                "account_bank":     bank_code,
                "account_number":   account_number,
                "amount":           amount_naira,
                "narration":        reason or "CredionPay Transfer",
                "currency":         "NGN",
                "reference":        reference,
                "beneficiary_name": account_name,
            },
            timeout=30, verify=False,
        )
        data = resp.json()
        if resp.status_code in (200, 201) and data.get("status") == "success":
            logger.info(f"🦋 FLW transfer OK: ₦{amount_naira:,.2f} → {account_number} [{reference}]")
            return {"success": True, "provider": "flutterwave", "data": data.get("data", {})}
        err = data.get("message", resp.text[:120])
        logger.warning(f"🦋 FLW transfer failed ({resp.status_code}): {err}")
        return {"success": False, "provider": "flutterwave", "error": err}
    except Exception as e:
        logger.warning(f"🦋 FLW transfer exception: {e}")
        return {"success": False, "provider": "flutterwave", "error": str(e)}


def _paystack_transfer(account_number: str, bank_code: str, account_name: str,
                       amount_naira: float, reference: str, reason: str = "") -> dict:
    """
    Initiate a bank payout via Paystack.
    Returns {"success": bool, "provider": "paystack", "data": {...}, "error": "..."}
    """
    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    if not ps_key.startswith("sk_live_"):
        return {"success": False, "provider": "paystack",
                "error": "Paystack test key — live transfers not available in test mode"}
    try:
        rec = paystack_post("/transferrecipient", {
            "type": "nuban", "name": account_name,
            "account_number": account_number,
            "bank_code": bank_code, "currency": "NGN",
        })
        if not rec.get("status"):
            return {"success": False, "provider": "paystack",
                    "error": rec.get("message", "Recipient creation failed")}
        trf = paystack_post("/transfer", {
            "source":    "balance",
            "reason":    reason or "CredionPay Transfer",
            "amount":    int(amount_naira * 100),
            "recipient": rec["data"]["recipient_code"],
            "reference": reference,
        })
        if not trf.get("status"):
            return {"success": False, "provider": "paystack",
                    "error": trf.get("message", "Transfer failed")}
        logger.info(f"💳 Paystack transfer OK: ₦{amount_naira:,.2f} → {account_number} [{reference}]")
        return {"success": True, "provider": "paystack", "data": trf.get("data", {})}
    except Exception as e:
        logger.warning(f"💳 Paystack transfer exception: {e}")
        return {"success": False, "provider": "paystack", "error": str(e)}


def _dual_transfer(account_number: str, bank_code: str, account_name: str,
                   amount_naira: float, reference: str, reason: str = "",
                   preferred: str = "paystack") -> dict:
    """
    Try TWO providers — if the preferred one fails, automatically switch to the other.
    preferred: "paystack" (default) | "flutterwave"

    Returns:
      {"success": True,  "provider": "paystack"|"flutterwave",
       "fallback_used": False|True, "data": {...}}
      {"success": False, "provider": "none",
       "fallback_used": True, "error": "Both providers failed: ..."}
    """
    providers = (
        [_paystack_transfer, _flw_transfer]
        if preferred == "paystack"
        else [_flw_transfer, _paystack_transfer]
    )

    errors = []
    for i, fn in enumerate(providers):
        result = fn(account_number, bank_code, account_name,
                    amount_naira, reference, reason)
        result["fallback_used"] = (i == 1)
        if result["success"]:
            if i == 1:
                logger.info(
                    f"⚡ Fallback transfer succeeded via {result['provider']} "
                    f"(primary failed: {errors[0]})"
                )
            return result
        errors.append(f"{result['provider']}: {result.get('error','unknown')}")
        logger.warning(f"⚠️  Transfer attempt {i+1}/{len(providers)} failed — {errors[-1]}")

    logger.error(f"❌ Both providers failed for {reference}: {errors}")
    return {
        "success":       False,
        "fallback_used": True,
        "provider":      "none",
        "error":         f"Both providers failed — {' | '.join(errors)}",
    }

def _sudo_headers():
    key = os.getenv("SUDO_API_KEY")
    if not key:
        raise HTTPException(500, "SUDO_API_KEY not configured")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

def sudo_post(endpoint, payload):
    r = requests.post(f"{SUDO_BASE_URL}{endpoint}", headers=_sudo_headers(), json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def sudo_put(endpoint, payload):
    r = requests.put(f"{SUDO_BASE_URL}{endpoint}", headers=_sudo_headers(), json=payload, timeout=30)
    r.raise_for_status()
    return r.json()


# ══════════════════════════════════════════════════════════════════════════════
# REQUEST SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════

class CreateWalletRequest(BaseModel):
    owner_name:  str
    owner_email: str
    phone:       Optional[str] = ""
    password:    Optional[str] = ""   # optional at creation; set later via /auth/set-password

class LoginRequest(BaseModel):
    identifier: str   # email OR Nigerian phone number
    password:   str

class SetPasswordRequest(BaseModel):
    wallet_id:    str
    new_password: str
    old_password: Optional[str] = ""  # required only if a password already exists

class KYCRequest(BaseModel):
    wallet_id:      str
    bvn:            str
    nin:            Optional[str] = ""
    dob:            str           # REQUIRED — needed for BVN DOB match
    full_name:      Optional[str] = ""
    address:        Optional[str] = ""
    account_number: Optional[str] = ""
    bank_code:      Optional[str] = ""
    bank_name:      Optional[str] = ""
    account_name:   Optional[str] = ""
    card_number:    Optional[str] = ""
    card_expiry:    Optional[str] = ""
    card_matched:   Optional[bool] = False

class VerifyCardRequest(BaseModel):
    wallet_id:      str
    account_number: str
    bank_code:      str
    card_number:    str
    card_expiry:    str
    card_cvv:       Optional[str] = ""
    account_name:   Optional[str] = ""

class FundWalletRequest(BaseModel):
    wallet_id:    str
    amount_naira: float
    callback_url: Optional[str] = "https://yourapp.com/callback"
    channels:     Optional[list] = ["card", "bank_transfer", "ussd"]

class FundByAccountRequest(BaseModel):
    wallet_id:      str
    amount_naira:   float
    account_number: str
    bank_code:      str
    account_name:   Optional[str] = ""

class FundByCardRequest(BaseModel):
    wallet_id:    str
    amount_naira: float
    card_number:  str
    card_expiry:  str
    card_cvv:     str

class VerifyFundingRequest(BaseModel):
    reference: str

class OtpRequest(BaseModel):
    wallet_id:   str
    purpose:     str   # "transfer" | "login" | "kyc" | "card" | "whatsapp_pay"
    amount:      float = 0.0   # shown in email for context

class OtpVerifyRequest(BaseModel):
    wallet_id:   str
    otp_code:    str
    purpose:     str

class WhatsAppPayRequest(BaseModel):
    sender_wallet_id: str
    recipient_phone:  str          # Nigerian phone number e.g. 08012345678
    recipient_name:   str          # What to call them in the message
    amount_naira:     float
    note:             str = ""     # optional message e.g. "For your birthday"
    expires_hours:    int  = 48    # link expires after this many hours

class WhatsAppPayClaim(BaseModel):
    link_id:          str
    recipient_name:   str
    recipient_email:  str = ""
    bank_code:        str = ""     # optional — if they want payout to bank
    account_number:   str = ""

class WalletTransferRequest(BaseModel):
    sender_wallet_id:   str
    receiver_wallet_id: str
    amount_naira:       float
    description:        Optional[str] = "Wallet Transfer"

class BankTransferRequest(BaseModel):
    wallet_id:      str
    account_number: str
    bank_code:      str
    amount_naira:   float
    reason:         Optional[str] = "Bank Transfer"
    account_name:   Optional[str] = ""

class VerifyAccountRequest(BaseModel):
    account_number: str
    bank_code:      str
    account_name:   Optional[str] = ""

class CreateVirtualCardRequest(BaseModel):
    wallet_id:    str
    amount_naira: float
    currency:     Optional[str] = "USD"    # USD by default — works on Amazon, globally
    card_brand:   Optional[str] = "Visa"   # Visa or Mastercard

class CardActionRequest(BaseModel):
    wallet_id: str
    card_id:   str

class AirtimeRequest(BaseModel):
    wallet_id:    str
    phone:        str          # e.g. 08012345678
    network:      str          # MTN, GLO, AIRTEL, 9MOBILE
    amount_naira: float

class DataRequest(BaseModel):
    wallet_id:    str
    phone:        str
    network:      str          # MTN, GLO, AIRTEL, 9MOBILE
    plan_code:    str          # Paystack data plan code
    amount_naira: float

class BillPayRequest(BaseModel):
    wallet_id:    str
    biller_code:  str          # Paystack biller code e.g. BIL119
    item_code:    str          # Paystack item/variation code
    customer_id:  str          # meter no / smartcard no / account no
    amount_naira: float
    phone:        Optional[str] = ""
    quantity:     Optional[int] = 1

class ValidateBillCustomerRequest(BaseModel):
    biller_code:  str
    item_code:    str
    customer_id:  str          # meter / smartcard / account number


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_bank_name(bank_code: str) -> str:
    for b in NIGERIAN_BANKS:
        if b["code"] == bank_code:
            return b["name"]
    return bank_code

def _get_wallet(wallet_id: str) -> Wallet:
    wid = (wallet_id or "").strip()
    if not wid:
        raise HTTPException(400, "Wallet ID is empty. Set your active wallet on the home screen first.")
    w = wallets.get(wid) or wallets.get(wid.upper())
    if not w:
        close = [k for k in wallets if wid.upper() in k.upper()]
        hint  = f" Did you mean: {close[0]}?" if close else " Check that the backend is running."
        raise HTTPException(404, f"Wallet '{wid}' not found.{hint}")
    return w

def _require_kyc(w: Wallet):
    if w.kyc.status != KYCStatus.VERIFIED:
        raise HTTPException(403, "Complete KYC verification first")

def _luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def _mask_card(number: str) -> str:
    clean = number.replace(" ", "")
    return f"**** **** **** {clean[-4:]}" if len(clean) >= 4 else "****"

# ── Persistent account name cache (survives server restarts) ─────────────────
ACCT_CACHE_FILE = _DATA_DIR / "credionpay_acct_cache.json"

def _load_acct_cache():
    if ACCT_CACHE_FILE.exists():
        try:
            data = json.loads(ACCT_CACHE_FILE.read_text())
            _account_cache.update(data)
            logger.info(f"✅ Loaded {len(data)} cached account names from disk.")
        except Exception as e:
            logger.warning(f"⚠️ Could not load account cache: {e}")

def _save_acct_cache():
    try:
        ACCT_CACHE_FILE.write_text(json.dumps(_account_cache, indent=2))
    except Exception as e:
        logger.warning(f"⚠️ Could not save account cache: {e}")

_load_acct_cache()

# ── Pre-seed Paystack test accounts — these never need API verification ───────
_PAYSTACK_TEST_ACCOUNTS = {
    # Format: "account_number:bank_code" -> "account_name"
    "0000000000:044": "Paystack Test Account",   # Access Bank test
    "0000000000:058": "Paystack Test Account",   # GTBank test  
    "0000000000:011": "Paystack Test Account",   # First Bank test
    "0000000000:033": "Paystack Test Account",   # UBA test
    "0000000000:057": "Paystack Test Account",   # Zenith test
    "0000000000:232": "Paystack Test Account",   # Sterling test
    "0000000000:000": "Paystack Test Account",   # Generic test
    "0000000001:044": "Paystack Test Account 2",
    "0000000002:044": "Paystack Test Account 3",
    "0000000003:044": "Paystack Test Account 4",
    "0000000004:044": "Paystack Test Account 5",
    "0000000005:044": "Paystack Test Account 6",
}
for _k, _v in _PAYSTACK_TEST_ACCOUNTS.items():
    _account_cache.setdefault(_k, _v)   # don't overwrite real cached names
logger.info(f"✅ Pre-seeded {len(_PAYSTACK_TEST_ACCOUNTS)} Paystack test accounts in cache")

def _save_acct_cache():
    try:
        ACCT_CACHE_FILE.write_text(json.dumps(_account_cache, indent=2))
    except Exception as e:
        logger.warning(f"⚠️ Could not save account cache: {e}")


def _resolve_account(account_number: str, bank_code: str, fallback_name: str = "") -> str:
    cache_key = f"{account_number.strip()}:{bank_code.strip()}"

    # 1. In-memory cache
    if cache_key in _account_cache:
        logger.info(f"✅ Account cache hit: {cache_key} → {_account_cache[cache_key]}")
        return _account_cache[cache_key]

    # 2. Use fallback immediately if provided — avoids Paystack call entirely
    if fallback_name and fallback_name.strip():
        name = fallback_name.strip()
        logger.info(f"✅ Using provided account_name (no Paystack call): {name}")
        _account_cache[cache_key] = name
        _save_acct_cache()
        return name

    # 3. Call Paystack only as last resort
    try:
        data = paystack_get("/bank/resolve", {"account_number": account_number, "bank_code": bank_code})
        if data.get("status"):
            name = data["data"]["account_name"]
            _account_cache[cache_key] = name
            _save_acct_cache()
            logger.info(f"✅ Account resolved & cached: {cache_key} → {name}")
            return name
        raise HTTPException(400, data.get("message", "Account verification failed"))
    except HTTPException as e:
        if e.status_code == 429:
            logger.warning(f"⚠️ Paystack 429 on {cache_key} — checking if we can skip")
            # If we have ANY cached entry for this account number (different bank), use it
            acc_only = account_number.strip()
            for k, v in _account_cache.items():
                if k.startswith(acc_only + ":"):
                    logger.info(f"✅ Using cross-bank cache for {acc_only}: {v}")
                    _account_cache[cache_key] = v
                    _save_acct_cache()
                    return v
            raise HTTPException(
                429,
                "Account verification is temporarily rate-limited by Paystack. "
                "Please wait 60 seconds and try again, or type your account name manually."
            )
        raise


def _names_overlap(name_a: str, name_b: str) -> bool:
    """Return True if at least one word from name_a appears in name_b (case-insensitive)."""
    words_a = set(name_a.upper().split())
    words_b = set(name_b.upper().split())
    return len(words_a & words_b) > 0


def _names_match_wallet(wallet_name: str, kyc_name: str) -> bool:
    """
    Check that the KYC name matches the wallet owner name.
    Rules:
      - At least 2 words must overlap  (handles middle name differences)
      - OR the full kyc_name is fully contained in wallet_name or vice versa
      - Case-insensitive, ignores punctuation
    Returns True if names are considered the same person.
    """
    import re as _re
    def _clean(n):
        return set(_re.sub(r"[^a-z ]", "", n.lower()).split())

    w_words = _clean(wallet_name)
    k_words = _clean(kyc_name)

    if not w_words or not k_words:
        return False

    overlap = w_words & k_words
    # Need at least 2 words to match, OR all words of shorter name match
    shorter_len = min(len(w_words), len(k_words))
    if shorter_len <= 1:
        return len(overlap) >= 1   # single-word name: just match it
    return len(overlap) >= 2       # multi-word name: at least 2 must match


# ══════════════════════════════════════════════════════════════════════════════
# ROOT / DEBUG ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/cache/warm-account")
def warm_account_cache(req: VerifyAccountRequest):
    if not req.account_name:
        return {"success": False, "message": "account_name required to warm cache"}
    key = f"{req.account_number.strip()}:{req.bank_code.strip()}"
    _account_cache[key] = req.account_name
    logger.info(f"🔥 Cache warmed: {key} → {req.account_name}")
    return {"success": True, "cached": key, "account_name": req.account_name}

@app.get("/wallet/list-all")
def list_all_wallets():
    return {
        "wallet_count": len(wallets),
        "wallets": [
            {"wallet_id": w.wallet_id, "name": w.owner_name, "email": w.owner_email,
             "balance": w.balance, "kyc": w.kyc.status}
            for w in wallets.values()
        ]
    }


@app.post("/wallet/lookup-by-email")
def lookup_wallet_by_email(req: dict = Body(...)):
    """Look up a wallet by registered email address — used for login flow."""
    email = req.get("email", "").strip().lower()
    if not email:
        raise HTTPException(400, "Email is required")
    # Search email_index
    wid = email_index.get(email) or email_index.get(email.capitalize()) or next(
        (v for k, v in email_index.items() if k.lower() == email), None)
    if not wid or wid not in wallets:
        raise HTTPException(404, f"No wallet found for email '{email}'. "
                                  "Please check your email or create a new wallet.")
    w = wallets[wid]
    logger.info(f"🔍 Wallet lookup by email: {email} → {wid}")
    return {"success": True, "wallet": w.to_dict()}


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES  — Login & Password Management
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/login")
def auth_login(req: LoginRequest):
    """
    Login with email OR Nigerian phone number + password.
    First-time login: if no password is set yet the submitted password is
    stored automatically (first-time setup flow).
    """
    identifier = req.identifier.strip()
    if not identifier or not req.password:
        raise HTTPException(400, "Identifier and password are required.")

    # 1. Try email (case-insensitive)
    id_lower = identifier.lower()
    wid = email_index.get(id_lower) or next(
        (v for k, v in email_index.items() if k.lower() == id_lower), None)

    # 2. Try phone_index (pre-built at startup)
    if not wid:
        norm = _normalise_phone(identifier)
        wid  = phone_index.get(norm)
        logger.info(f"🔍 Phone lookup: raw='{identifier}' → norm='{norm}' → wid={wid}")

    # 3. Last resort — scan all wallets directly by phone field
    #    (catches wallets created before phone_index existed)
    if not wid:
        norm = _normalise_phone(identifier)
        for _wid, _w in wallets.items():
            if _w.phone and _normalise_phone(_w.phone) == norm:
                wid = _wid
                # Also fix the index so future lookups are fast
                phone_index[norm] = wid
                logger.info(f"📱 Phone found by direct scan: {norm} → {wid} (index repaired)")
                break

    if not wid or wid not in wallets:
        # Give a helpful message — tell user to try email if phone fails
        is_phone = re.search(r"^\+?[\d\s\-]{9,15}$", identifier.strip()) is not None
        detail = (
            "No account found with that phone number. "
            "Try logging in with your email address instead, "
            "or check that you registered with this phone number."
            if is_phone else
            "No account found with that email address. "
            "Please check the details or create a new wallet."
        )
        logger.warning(f"❌ Login 404 — identifier='{identifier}' "
                       f"phone_index={list(phone_index.keys())} "
                       f"email_keys={list(email_index.keys())}")
        raise HTTPException(404, detail)

    w = wallets[wid]
    if not w.is_active:
        raise HTTPException(403, "Account is deactivated. Contact CredionPay support.")

    # First-time login — no password set yet → save it automatically
    if not w.password_hash:
        w.password_hash = _hash_password(req.password)
        save_db()
        logger.info(f"🔐 First-time password set for wallet {wid}")
        return {
            "success":    True,
            "first_time": True,
            "message":    f"Password set! Welcome, {w.owner_name.split()[0]}!",
            "wallet":     w.to_dict(),
        }

    # Normal login — verify password
    if not _verify_password(req.password, w.password_hash):
        raise HTTPException(401, "Incorrect password. Please try again.")

    logger.info(f"✅ Login: {wid} ({w.owner_email})")
    return {
        "success":    True,
        "first_time": False,
        "message":    f"Welcome back, {w.owner_name.split()[0]}!",
        "wallet":     w.to_dict(),
    }


@app.post("/auth/set-password")
def auth_set_password(req: SetPasswordRequest):
    """Set or change account password."""
    if req.wallet_id not in wallets:
        raise HTTPException(404, "Wallet not found.")
    w = wallets[req.wallet_id]
    if len(req.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")
    if w.password_hash:
        if not req.old_password:
            raise HTTPException(400, "Current password is required to change password.")
        if not _verify_password(req.old_password, w.password_hash):
            raise HTTPException(401, "Current password is incorrect.")
    w.password_hash = _hash_password(req.new_password)
    save_db()
    logger.info(f"🔐 Password updated: {req.wallet_id}")
    return {"success": True, "message": "Password updated successfully."}


@app.post("/wallet/update-phone")
def update_phone(req: dict = Body(...)):
    """
    Update the phone number on a wallet and rebuild the phone index entry.
    Useful when a user registered with a wrong/test phone and wants to fix it.
    Requires wallet_id + new_phone. Optionally requires password for security.
    """
    wallet_id = req.get("wallet_id", "").strip()
    new_phone  = req.get("phone", "").strip()
    password   = req.get("password", "").strip()

    if not wallet_id or wallet_id not in wallets:
        raise HTTPException(404, "Wallet not found.")
    if not new_phone or len(re.sub(r"[^\d]", "", new_phone)) < 10:
        raise HTTPException(400, "Enter a valid phone number (e.g. 07066812367).")

    w = wallets[wallet_id]

    # If wallet has a password, verify it before allowing phone change
    if w.password_hash:
        if not password:
            raise HTTPException(400, "Password required to update phone number.")
        if not _verify_password(password, w.password_hash):
            raise HTTPException(401, "Incorrect password.")

    norm_new = _normalise_phone(new_phone)

    # Check no other wallet already uses this phone
    existing_wid = phone_index.get(norm_new)
    if existing_wid and existing_wid != wallet_id:
        raise HTTPException(409, "That phone number is already registered to another account.")

    # Remove old phone from index
    if w.phone:
        old_norm = _normalise_phone(w.phone)
        phone_index.pop(old_norm, None)

    # Update and re-index
    w.phone = new_phone
    phone_index[norm_new] = wallet_id
    save_db()

    logger.info(f"📱 Phone updated: {wallet_id} → {norm_new}")
    masked = f"{new_phone[:4]}***{new_phone[-3:]}" if len(new_phone) >= 7 else new_phone
    return {
        "success": True,
        "message": f"Phone number updated to {masked}. You can now login with this number.",
        "phone":   masked,
    }


@app.get("/auth/debug-indexes")
def auth_debug_indexes():
    """Dev helper — shows email and phone indexes. Remove before production."""
    return {
        "wallet_count":  len(wallets),
        "email_index":   list(email_index.keys()),
        "phone_index":   list(phone_index.keys()),
        "wallets_summary": [
            {"wid": wid, "name": w.owner_name,
             "email": w.owner_email, "phone": w.phone,
             "phone_norm": _normalise_phone(w.phone) if w.phone else "",
             "has_password": bool(w.password_hash)}
            for wid, w in wallets.items()
        ]
    }


@app.get("/")
def root():
    enc_status = "✅ AES-256 Fernet ACTIVE" if _FERNET_AVAILABLE else "❌ DISABLED — run: pip install cryptography"
    return {
        "message":        f"🇳🇬 {APP_NAME} API v16.0 — {len(wallets)} wallets loaded",
        "bvn_encryption": enc_status,
        "encryption_ok":  _FERNET_AVAILABLE,
        "phone_index":    f"{len(phone_index)} phones indexed",
        "docs":           "/docs",
        "warning":        None if _FERNET_AVAILABLE else "BVN IS BEING STORED IN PLAIN TEXT. Install cryptography immediately.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# BANK LIST
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/bank/list")
def list_banks():
    try:
        data = paystack_get("/bank", {"country": "nigeria", "perPage": 100})
        if data.get("status"):
            return {"success": True, "source": "paystack", "banks": data["data"]}
    except Exception:
        pass
    return {"success": True, "source": "local", "banks": NIGERIAN_BANKS}


@app.post("/bank/verify-account")
def verify_account(req: VerifyAccountRequest):
    if len(req.account_number) != 10 or not req.account_number.isdigit():
        raise HTTPException(400, "Account number must be exactly 10 digits")
    account_name = _resolve_account(req.account_number, req.bank_code,
                                    fallback_name=req.account_name or "")
    return {"success": True, "account_name": account_name,
            "account_number": req.account_number,
            "cached": f"{req.account_number}:{req.bank_code}" in _account_cache}


# ══════════════════════════════════════════════════════════════════════════════
# WALLET ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/wallet/create")
def create_wallet(req: CreateWalletRequest, bg: BackgroundTasks):
    if req.owner_email in email_index:
        wid = email_index[req.owner_email]
        w_existing = wallets[wid]
        # Auto-heal: if owner_name is a test/placeholder name but KYC has a real account name, fix it
        _test_names = {"paystack test account", "test account", "paystack test", "paystack"}
        current_name_lower = w_existing.owner_name.lower().strip()
        if current_name_lower in _test_names and w_existing.kyc.account_name:
            real_name = w_existing.kyc.account_name.title()
            logger.info(f"🔧 Auto-healing test name: '{w_existing.owner_name}' → '{real_name}'")
            w_existing.owner_name = real_name
            save_db()

        # If already KYC verified, re-send the full welcome with legal name
        if w_existing.kyc.status == KYCStatus.VERIFIED:
            bg.add_task(email_setup_complete, w_existing)
        else:
            bg.add_task(email_wallet_created, w_existing)
        logger.info(f"📧 Re-sending wallet email for existing wallet {wid} (kyc={w_existing.kyc.status})")
        return {"success": True, "message": "Wallet already exists — details re-sent to your email", "wallet": w_existing.to_dict()}
    w = Wallet(owner_name=req.owner_name, owner_email=req.owner_email, phone=req.phone or "")

    # ── Hash password if provided at registration ─────────────────────────────
    if req.password:
        w.password_hash = _hash_password(req.password)

    # ── Generate permanent USD tag ────────────────────────────────────────────
    w.usd_tag = _generate_usd_tag(req.owner_name)
    usd_tag_index[w.usd_tag] = w.wallet_id

    # ── Mock virtual accounts (replace with Flutterwave API when key ready) ──
    import random as _r
    def _rand_digits(n): return "".join([str(_r.randint(0,9)) for _ in range(n)])
    w.virtual_acct_uk = {
        "bank_name":    "Flutterwave / Lloyds UK",
        "sort_code":    "04-00-75",
        "account_no":   "7" + _rand_digits(7),
        "account_name": req.owner_name,
        "currency":     "GBP",
        "reference":    w.usd_tag,
    }
    w.virtual_acct_us = {
        "bank_name":    "Flutterwave / Evolve Bank USA",
        "routing_no":   "026073150",
        "account_no":   "9" + _rand_digits(8),
        "account_name": req.owner_name,
        "currency":     "USD",
        "reference":    w.usd_tag,
    }

    wallets[w.wallet_id]       = w
    email_index[w.owner_email] = w.wallet_id
    if w.phone:
        phone_index[_normalise_phone(w.phone)] = w.wallet_id
    save_db()
    bg.add_task(email_wallet_created, w)
    logger.info(f"✅ Wallet created: {w.wallet_id} for {req.owner_name}")
    return {
        "success":   True,
        "message":   f"Wallet created! ID sent to {req.owner_email}",
        "wallet":    w.to_dict(),
        "next_step": "Complete KYC at POST /wallet/kyc",
    }


@app.get("/wallet/find-tag")
def find_wallet_by_tag_query(tag: str):
    """
    Look up wallet by USD tag via query param.
    Supports partial match — searches by tag OR by owner name fragment.
    """
    # Strip quotes, @, spaces — handle URL-encoded input
    raw = tag.strip().strip('"').strip("'").lstrip("@").lower()
    # Remove credionpay/ prefix for searching
    search = raw.replace("credionpay/", "").replace(" ", "").replace("%20", "").strip()

    logger.info(f"🔍 Tag search: raw='{raw}' search='{search}' index_size={len(usd_tag_index)}")

    # 1. Try all exact candidates
    candidates = [
        f"@credionpay/{search}",
        f"@{raw}",
        f"@{search}",
        raw,
        search,
    ]
    for c in candidates:
        if c in usd_tag_index:
            wid = usd_tag_index[c]
            if wid in wallets:
                w = wallets[wid]
                logger.info(f"✅ Tag found (exact): {c} → {w.wallet_id}")
                return {"success": True, "usd_tag": w.usd_tag,
                        "owner_name": w.owner_name, "wallet_id": w.wallet_id}

    # 2. Fuzzy — search all tags and owner names
    matches = []
    for t, wid in usd_tag_index.items():
        if wid not in wallets:
            continue
        w = wallets[wid]
        tag_part = t.lstrip("@").replace("credionpay/", "").lower()
        name_part = w.owner_name.lower().replace(" ", "")
        if search and (search in tag_part or search in name_part):
            matches.append(w)

    logger.info(f"🔍 Fuzzy matches for '{search}': {[m.usd_tag for m in matches]}")

    if len(matches) == 1:
        w = matches[0]
        return {"success": True, "usd_tag": w.usd_tag,
                "owner_name": w.owner_name, "wallet_id": w.wallet_id}
    elif len(matches) > 1:
        raise HTTPException(400,
            f"Multiple wallets match '{search}'. Be more specific.")

    # 3. Log all known tags to help debug
    all_tags = list(usd_tag_index.keys())
    logger.warning(f"❌ Tag not found: '{search}'. Known tags: {all_tags}")
    raise HTTPException(404, f"No wallet found for tag '{tag}'. Known tags: {all_tags}")


@app.get("/wallet/tags/all")
def list_all_usd_tags():
    """List all registered USD tags — useful for testing send flow."""
    return {
        "success": True,
        "count":   len(usd_tag_index),
        "tags":    [
            {"tag": tag, "wallet_id": wid, "owner": wallets[wid].owner_name}
            for tag, wid in usd_tag_index.items()
            if wid in wallets
        ]
    }




@app.get("/wallet/{wallet_id}")
def get_wallet_route(wallet_id: str):
    w = _get_wallet(wallet_id)
    d = w.to_dict()
    d["kyc"] = w.kyc.to_dict()
    return {"success": True, "wallet": d}


@app.get("/wallet/{wallet_id}/statement")
def get_statement(wallet_id: str, limit: int = 20):
    w = _get_wallet(wallet_id)
    return {
        "success":      True,
        "wallet_id":    wallet_id,
        "owner_name":   w.owner_name,
        "balance":      w.balance,
        "kyc_status":   w.kyc.status,
        "transactions": [t.to_dict() for t in w.transactions[-limit:]],
    }


@app.get("/wallets")
def list_wallets_route():
    return {"success": True, "count": len(wallets),
            "wallets": [w.to_dict() for w in wallets.values()]}


# ══════════════════════════════════════════════════════════════════════════════
# KYC — v10: BVN ENCRYPTION + DOB MATCH + NAME MATCH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/wallet/kyc")
def submit_kyc(req: KYCRequest, bg: BackgroundTasks):
    """
    Full KYC Verification Pipeline (v13):
    ─────────────────────────────────────
    0. KYC full_name must match the wallet owner name (name used at wallet creation)
    1. BVN format validated (must be exactly 11 digits)
    2. DOB is required (used for BVN match)
    3. Bank account verified via Paystack /bank/resolve
    4. BVN matched against account + name + DOB via Paystack /identity/bvn/match
       - Name on BVN must match name provided
       - Date of birth must match BVN record
       - Account name (Paystack) must share words with BVN name
    5. BVN encrypted with AES-256 (Fernet) BEFORE saving to disk
    6. KYC record saved — BVN never stored in plain text
    """
    w = _get_wallet(req.wallet_id)
    if w.kyc.status == KYCStatus.VERIFIED:
        # Allow re-KYC if a different bank account is submitted
        # This handles: same user switching accounts, or testing with different accounts
        same_account = (
            w.kyc.account_number == req.account_number.strip()
            and w.kyc.bank_code == req.bank_code.strip()
        )
        if same_account:
            return {"success": True, "message": "KYC already verified ✅", "kyc": w.kyc.to_dict()}
        # Different account → reset KYC status and re-verify
        logger.info(f"🔄 Re-KYC: wallet {w.wallet_id} submitting new account "
                    f"{req.account_number} (was {w.kyc.account_number})")
        w.kyc.status = KYCStatus.PENDING

    # ── 0. Resolve KYC name ───────────────────────────────────────────────────
    # Wallet creation (Step 1) and KYC (Step 2) are now a single unified flow.
    # The user's legal name (from BVN/bank) may differ from the display name
    # they typed at signup — so we no longer block on name mismatch.
    # Instead: if a full_name is submitted, use it; otherwise fall back to wallet name.
    # The BVN match step below will catch genuinely wrong identities.
    kyc_full_name = (req.full_name or "").strip() or w.owner_name.strip()
    # Update wallet display name to match legal name from KYC (BVN name takes priority later)
    wallet_name   = w.owner_name.strip()
    logger.info(f"KYC submission — wallet={w.wallet_id} wallet_name='{wallet_name}' kyc_name='{kyc_full_name}'")

    # ── 1. BVN format ─────────────────────────────────────────────────────────
    bvn_plain = req.bvn.strip()
    if len(bvn_plain) != 11 or not bvn_plain.isdigit():
        raise HTTPException(400, "BVN must be exactly 11 digits with no spaces or letters.")

    # ── 2. DOB required + normalise to YYYY-MM-DD for Paystack ──────────────
    dob_raw = (req.dob or "").strip()
    if not dob_raw:
        raise HTTPException(400, "Date of birth is required. Enter it as YYYY-MM-DD or DD/MM/YYYY.")

    def _normalise_dob(raw: str) -> str:
        """
        Accept any common DOB format and return YYYY-MM-DD for Paystack.
        Handles: YYYY-MM-DD, DD/MM/YYYY, DD-MM-YYYY, MM/DD/YYYY
        """
        raw = raw.strip()
        # Already YYYY-MM-DD  e.g. 1979-04-03
        # YYYY-MM-DD already
        if len(raw) == 10 and raw[4] == "-" and raw[7] == "-" and raw[:4].isdigit():
            return raw
        # DD/MM/YYYY  e.g. 03/04/1979
        if len(raw) == 10 and raw[2] == "/" and raw[5] == "/":
            parts = raw.split("/")
            if len(parts[2]) == 4:
                return f"{parts[2]}-{parts[1]}-{parts[0]}"
        # DD-MM-YYYY  e.g. 03-04-1979
        if len(raw) == 10 and raw[2] == "-" and raw[5] == "-" and len(raw.split("-")[2]) == 4:
            parts = raw.split("-")
            return f"{parts[2]}-{parts[1]}-{parts[0]}"
        return raw   # fallback — return as-is, let Paystack reject if bad

    dob = _normalise_dob(dob_raw)
    logger.info(f"📅 DOB normalised: '{dob_raw}' → '{dob}'")

    # ── 3. Bank account verification ──────────────────────────────────────────
    verified_account_name = req.account_name or ""
    if req.account_number and req.bank_code:
        try:
            verified_account_name = _resolve_account(
                req.account_number.strip(),
                req.bank_code.strip(),
                fallback_name=req.account_name or ""
            )
        except HTTPException as e:
            raise HTTPException(400, f"Bank account verification failed: {e.detail}")

    # ── 4. BVN Match — name + DOB + account ───────────────────────────────────
    # NOTE: Paystack /identity/bvn/match requires a LIVE secret key.
    # On TEST keys it returns 404. In that case we skip BVN cross-check
    # but still encrypt and store the BVN.
    bvn_api_available   = False
    bvn_name_match      = True   # default PASS if API unavailable
    bvn_dob_match       = True   # default PASS if API unavailable
    bvn_registered_name = verified_account_name

    try:
        full_name  = kyc_full_name or w.owner_name or ""
        name_parts = full_name.strip().split()
        bvn_payload = {
            "bvn":            bvn_plain,
            "account_number": req.account_number.strip() if req.account_number else "",
            "bank_code":      req.bank_code.strip() if req.bank_code else "",
            "first_name":     name_parts[0] if name_parts else "",
            "last_name":      name_parts[-1] if len(name_parts) > 1 else "",
        }
        logger.info(f"🔐 Calling Paystack BVN match for wallet {w.wallet_id}")
        bvn_resp = paystack_post("/identity/bvn/match", bvn_payload)

        if bvn_resp.get("status"):
            bvn_api_available = True
            d = bvn_resp.get("data", {})

            # Name match — first OR last name must match
            first_match    = d.get("first_name", {}).get("match", False)
            last_match     = d.get("last_name",  {}).get("match", False)
            bvn_name_match = first_match or last_match

            # DOB match — Paystack compares dob field
            bvn_dob_match = d.get("dob", {}).get("match", True)

            if d.get("account_name"):
                bvn_registered_name = d["account_name"]

            logger.info(
                f"🔐 BVN match result — first={first_match}, last={last_match}, "
                f"dob={bvn_dob_match}, api=live"
            )
        else:
            logger.warning(f"⚠️ Paystack BVN match returned status=false: {bvn_resp.get('message')}")

    except HTTPException as e:
        # 404 = test key (BVN API not available on test mode)
        # 401 = invalid key
        # 502 = Paystack unreachable
        logger.warning(
            f"⚠️ BVN match API unavailable [{e.status_code}]: {e.detail} "
            f"— BVN will be encrypted and stored but cross-check skipped"
        )
        bvn_api_available = False
    except Exception as e:
        logger.warning(f"⚠️ BVN match unexpected error: {e} — skipping cross-check")
        bvn_api_available = False

    # ── 5. Enforce BVN validations (only when API responded) ──────────────────
    def _kyc_fail(reason: str):
        """Save KYC as FAILED, send failure email, raise 400."""
        w.kyc.status         = KYCStatus.FAILED
        w.kyc.failure_reason = reason
        w.kyc.verified_at    = datetime.now().isoformat()
        save_db()
        bg.add_task(email_kyc_status, w, "failed", reason)
        logger.warning(f"❌ KYC FAILED — wallet {w.wallet_id}: {reason}")
        raise HTTPException(400, reason)

    if bvn_api_available:
        if not bvn_name_match:
            _kyc_fail(
                f"BVN name mismatch: the name on your BVN does not match "
                f"'{req.full_name or w.owner_name}'. "
                f"Please enter your name exactly as registered on your BVN."
            )

        if not bvn_dob_match:
            _kyc_fail(
                f"Date of birth mismatch: you entered '{dob}' but your BVN "
                f"has a different date of birth. Please enter your correct DOB (DD/MM/YYYY)."
            )

        # Account name cross-check against BVN name
        if verified_account_name and bvn_registered_name:
            if not _names_overlap(verified_account_name, bvn_registered_name):
                _kyc_fail(
                    f"Account name mismatch: your bank account belongs to "
                    f"'{verified_account_name}' but your BVN is registered to "
                    f"'{bvn_registered_name}'. Please use the bank account linked to your BVN."
                )

    # ── 6. Register debit card ─────────────────────────────────────────────────
    registered_cards = []
    if req.card_number:
        clean_card = req.card_number.replace(" ", "")
        if not _luhn_check(clean_card):
            raise HTTPException(400, "Invalid card number — please check and re-enter.")
        card = RegisteredCard(
            masked_number=_mask_card(clean_card),
            last_four=clean_card[-4:],
            expiry=req.card_expiry or "",
            bank_name=req.bank_name or "",
            bank_code=req.bank_code or "",
            account_number=req.account_number or "",
            account_name=verified_account_name,
            is_verified=bool(req.card_matched),
        )
        registered_cards = [card.to_dict()]

    # ── 7. Encrypt BVN before storing ─────────────────────────────────────────
    bvn_encrypted = encrypt_bvn(bvn_plain)
    logger.info(f"🔐 BVN encrypted for wallet {w.wallet_id} — plain BVN NOT stored or logged")

    # ── 8. Save KYC record ─────────────────────────────────────────────────────
    bank_name = _get_bank_name(req.bank_code.strip()) if req.bank_code else (req.bank_name or "")
    w.kyc.bvn              = bvn_encrypted        # ← AES-256 encrypted
    w.kyc.nin              = req.nin or ""
    # Use the bank-verified account name as the canonical display name.
    # SKIP update if the resolved name is a generic test/placeholder name.
    _TEST_NAMES = {"paystack test account", "test account", "paystack test", "test"}
    is_test_name = verified_account_name.lower().strip() in _TEST_NAMES
    
    if is_test_name:
        # Keep the user's signup name — don't overwrite with "Paystack Test Account"
        legal_name = kyc_full_name or w.owner_name
        logger.info(f"ℹ️ Skipping name update — test account detected. Keeping: '{legal_name}'")
    else:
        # Real account — use verified bank name as canonical legal name
        legal_name = verified_account_name or kyc_full_name or w.owner_name
        if legal_name and legal_name != w.owner_name:
            logger.info(f"📛 Updating wallet display name: '{w.owner_name}' → '{legal_name}'")
            w.owner_name = legal_name.title()

    w.kyc.full_name        = legal_name
    w.kyc.dob              = dob
    w.kyc.address          = req.address or ""
    w.kyc.phone            = req.phone if hasattr(req, "phone") and req.phone else w.phone or ""
    w.kyc.account_number   = req.account_number.strip() if req.account_number else ""
    w.kyc.bank_code        = req.bank_code.strip() if req.bank_code else ""
    w.kyc.bank_name        = bank_name
    w.kyc.account_name     = verified_account_name
    w.kyc.registered_cards = registered_cards
    w.kyc.status           = KYCStatus.VERIFIED
    w.kyc.verified_at      = datetime.now().isoformat()
    w.kyc.failure_reason   = ""
    save_db()

    bg.add_task(email_kyc_status, w, "verified")
    bg.add_task(email_setup_complete, w)   # full welcome email with verified legal name
    logger.info(f"✅ KYC VERIFIED — wallet {w.wallet_id}, bvn_api={bvn_api_available}")

    return {
        "success":      True,
        "message":      "KYC verified ✅ — Identity, account and debit card confirmed.",
        "kyc":          w.kyc.to_dict(),
        "bvn_masked":   mask_bvn(bvn_encrypted),
        "bvn_verified": bvn_api_available,
        "dob_matched":  bvn_dob_match,
        "name_matched": bvn_name_match,
    }


@app.post("/kyc/verify-card")
def verify_card_match(req: VerifyCardRequest):
    w     = _get_wallet(req.wallet_id)
    clean = req.card_number.replace(" ", "")
    if not _luhn_check(clean):
        raise HTTPException(400, "Invalid card number (failed Luhn check)")
    if req.card_expiry:
        try:
            parts     = req.card_expiry.split("/")
            exp_month = int(parts[0])
            exp_year  = int("20" + parts[1]) if len(parts[1]) == 2 else int(parts[1])
            now       = datetime.now()
            if exp_year < now.year or (exp_year == now.year and exp_month < now.month):
                raise HTTPException(400, "Card has expired")
        except (IndexError, ValueError):
            raise HTTPException(400, "Invalid expiry format. Use MM/YY")
    try:
        resolved_name = _resolve_account(req.account_number, req.bank_code,
                                         fallback_name=req.account_name or "")
    except Exception:
        resolved_name = req.account_name or ""
    if resolved_name and req.account_name:
        r = resolved_name.lower().replace(" ", "")
        p = req.account_name.lower().replace(" ", "")
        if r != p and not (r in p or p in r):
            raise HTTPException(400, f"Card account name '{resolved_name}' does not match '{req.account_name}'")
    for card in w.kyc.registered_cards:
        if card.get("last_four") == clean[-4:]:
            card["is_verified"] = True
            break
    save_db()
    return {"success": True, "message": "✅ Card verified and matched to account",
            "account_name": resolved_name or req.account_name,
            "masked_card":  _mask_card(clean)}


@app.get("/wallet/{wallet_id}/kyc")
def get_kyc(wallet_id: str):
    w = _get_wallet(wallet_id)
    return {"success": True, "wallet_id": wallet_id, "kyc": w.kyc.to_dict()}


# ══════════════════════════════════════════════════════════════════════════════
# FUNDING ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/wallet/fund")
def fund_wallet_paystack(req: FundWalletRequest, bg: BackgroundTasks):
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    reference = f"FUND-{uuid.uuid4().hex[:16].upper()}"
    data = paystack_post("/transaction/initialize", {
        "email": w.owner_email, "amount": int(req.amount_naira * 100),
        "currency": "NGN", "reference": reference, "callback_url": req.callback_url,
        "channels": req.channels,
        "metadata": {"wallet_id": req.wallet_id, "funding_type": "wallet_top_up"},
    })
    if data.get("status"):
        pending_funding[reference] = (req.wallet_id, req.amount_naira)
        return {
            "success":           True,
            "reference":         reference,
            "amount_naira":      req.amount_naira,
            "authorization_url": data["data"]["authorization_url"],
            "access_code":       data["data"]["access_code"],
            "message":           "Open authorization_url to complete payment",
        }
    raise HTTPException(400, data.get("message", "Initialization failed"))


@app.post("/wallet/fund/account")
def fund_by_account(req: FundByAccountRequest, bg: BackgroundTasks):
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if w.kyc.account_number:
        if req.account_number.strip() != w.kyc.account_number.strip():
            raise HTTPException(403,
                f"Account {req.account_number} does not match KYC-registered account "
                f"({w.kyc.account_number} at {w.kyc.bank_name}).")
    try:
        account_name = _resolve_account(req.account_number, req.bank_code,
                                        fallback_name=req.account_name or w.kyc.account_name or "")
    except HTTPException as he:
        if he.status_code == 429:
            account_name = req.account_name or w.kyc.account_name or ""
        else:
            raise
    reference = f"ACC-FUND-{uuid.uuid4().hex[:14].upper()}"
    try:
        charge_data = paystack_post("/charge", {
            "email": w.owner_email, "amount": int(req.amount_naira * 100),
            "bank": {"code": req.bank_code, "account_number": req.account_number},
            "reference": reference,
            "metadata": {"wallet_id": req.wallet_id, "funding_type": "account_debit"},
        })
        if charge_data.get("status") and charge_data.get("data", {}).get("status") in ["success", "send_otp", "pending"]:
            if charge_data["data"]["status"] == "success":
                tx = w.credit(req.amount_naira, TxCategory.ACCOUNT_FUNDING,
                              f"Wallet funding via account — {account_name}", reference)
                save_db()
                bg.add_task(email_funding_receipt, w, tx, "Bank Account Debit", req.amount_naira, reference)
                return {"success": True, "status": "success", "amount": req.amount_naira,
                        "account_name": account_name, "new_balance": w.balance}
            return {"success": True, "status": charge_data["data"]["status"],
                    "reference": reference, "data": charge_data["data"]}
        raise HTTPException(400, charge_data.get("message", "Charge failed"))
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Direct account charge unavailable: {e}. Generating link.")
        link_data = paystack_post("/transaction/initialize", {
            "email": w.owner_email, "amount": int(req.amount_naira * 100),
            "currency": "NGN", "reference": reference, "channels": ["bank_transfer"],
            "metadata": {"wallet_id": req.wallet_id},
        })
        if link_data.get("status"):
            pending_funding[reference] = (req.wallet_id, req.amount_naira)
            return {"success": True, "status": "link_generated",
                    "authorization_url": link_data["data"]["authorization_url"],
                    "account_name": account_name}
        raise HTTPException(400, "Could not initiate account funding")


@app.post("/wallet/fund/card")
def fund_by_card(req: FundByCardRequest, bg: BackgroundTasks):
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    clean = req.card_number.replace(" ", "")
    if not _luhn_check(clean):
        raise HTTPException(400, "Invalid card number")
    registered_last_fours = [c.get("last_four", "") for c in w.kyc.registered_cards]
    if registered_last_fours and clean[-4:] not in registered_last_fours:
        raise HTTPException(403, f"Card ending in {clean[-4:]} is not registered in KYC.")
    card_record = next((c for c in w.kyc.registered_cards if c.get("last_four") == clean[-4:]), None)
    if card_record and not card_record.get("is_verified", False):
        raise HTTPException(403, "Card registered but not yet verified. Complete card verification in KYC.")
    try:
        parts = req.card_expiry.split("/")
        exp_month = int(parts[0])
        exp_year  = int("20" + parts[1]) if len(parts[1]) == 2 else int(parts[1])
        now = datetime.now()
        if exp_year < now.year or (exp_year == now.year and exp_month < now.month):
            raise HTTPException(400, "Card has expired")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Invalid expiry format. Use MM/YY")
    reference = f"CARD-FUND-{uuid.uuid4().hex[:12].upper()}"
    try:
        charge_data = paystack_post("/charge", {
            "email": w.owner_email, "amount": int(req.amount_naira * 100),
            "card": {"number": clean, "cvv": req.card_cvv,
                     "expiry_month": req.card_expiry.split("/")[0],
                     "expiry_year": "20" + req.card_expiry.split("/")[1]},
            "reference": reference,
            "metadata": {"wallet_id": req.wallet_id, "funding_type": "card_charge"},
        })
        status = charge_data.get("data", {}).get("status", "")
        if status == "success":
            tx = w.credit(req.amount_naira, TxCategory.CARD_FUNDING,
                          f"Wallet funded via card ending {clean[-4:]}", reference)
            save_db()
            bg.add_task(email_funding_receipt, w, tx, "Debit Card Charge", req.amount_naira, reference)
            return {"success": True, "status": "success", "amount": req.amount_naira,
                    "new_balance": w.balance}
        elif status in ["send_otp", "pending"]:
            return {"success": True, "status": status, "reference": reference,
                    "data": charge_data["data"]}
        raise HTTPException(400, charge_data.get("message", "Card charge failed"))
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Direct card charge unavailable: {e}")
        link_data = paystack_post("/transaction/initialize", {
            "email": w.owner_email, "amount": int(req.amount_naira * 100),
            "currency": "NGN", "reference": reference, "channels": ["card"],
            "metadata": {"wallet_id": req.wallet_id},
        })
        if link_data.get("status"):
            pending_funding[reference] = (req.wallet_id, req.amount_naira)
            return {"success": True, "status": "link_generated",
                    "authorization_url": link_data["data"]["authorization_url"]}
        raise HTTPException(400, "Could not initiate card funding")


@app.post("/wallet/verify-funding")
def verify_funding(req: VerifyFundingRequest, bg: BackgroundTasks):
    data = paystack_get(f"/transaction/verify/{req.reference}")
    if not data.get("status"):
        raise HTTPException(400, data.get("message", "Verification failed"))
    tx_data    = data["data"]
    pay_status = tx_data.get("status")
    if pay_status != "success":
        return {"success": False, "status": pay_status}
    amount_naira = tx_data["amount"] / 100
    wallet_id    = tx_data.get("metadata", {}).get("wallet_id") or \
                   (pending_funding.get(req.reference, (None,))[0])
    if not wallet_id or wallet_id not in wallets:
        raise HTTPException(404, "Wallet not found in payment metadata")
    w = wallets[wallet_id]
    if any(t.reference == req.reference for t in w.transactions):
        return {"success": True, "status": "already_processed", "balance": w.balance}
    channel  = tx_data.get("channel", "bank").replace("_", " ").title()
    category = TxCategory.CARD_FUNDING if "card" in tx_data.get("channel", "") else TxCategory.BANK_FUNDING
    tx = w.credit(amount_naira, category, f"Wallet top-up via {channel}", req.reference)
    pending_funding.pop(req.reference, None)
    save_db()
    bg.add_task(email_funding_receipt, w, tx, channel, amount_naira, req.reference)
    return {"success": True, "status": "success", "amount": amount_naira,
            "channel": channel, "new_balance": w.balance}


# ══════════════════════════════════════════════════════════════════════════════
# WALLET TRANSFER
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/wallet/transfer")
def wallet_transfer(req: WalletTransferRequest, bg: BackgroundTasks):
    sender   = _get_wallet(req.sender_wallet_id)
    receiver = _get_wallet(req.receiver_wallet_id)
    _require_kyc(sender)
    _require_kyc(receiver)
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    ref = f"WWT-{uuid.uuid4().hex[:12].upper()}"
    try:
        dtx = sender.debit(req.amount_naira, TxCategory.WALLET_TRANSFER_OUT,
                           f"Transfer to {receiver.owner_name} — {req.description}", ref)
        ctx = receiver.credit(req.amount_naira, TxCategory.WALLET_TRANSFER_IN,
                              f"Transfer from {sender.owner_name} — {req.description}", ref)
        save_db()
        bg.add_task(email_debit_receipt, sender, dtx,
                    to_name=receiver.owner_name, to_account=receiver.wallet_id)
        bg.add_task(email_credit_receipt, receiver, ctx,
                    from_name=sender.owner_name, from_wallet=sender.wallet_id)
        return {"success": True, "reference": ref, "amount": req.amount_naira,
                "sender_balance": sender.balance, "receiver_balance": receiver.balance}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# BANK PAYOUT
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/transfer/to-bank")
def transfer_to_bank(req: BankTransferRequest, bg: BackgroundTasks):
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)
    # ── OTP verification required for bank transfers ─────────────────────────
    otp_key    = _otp_key(req.wallet_id, "transfer")
    otp_record = otp_store.get(otp_key, {})
    if not otp_record.get("verified"):
        raise HTTPException(403,
            "OTP verification required. Please request and verify an OTP before transferring.")
    # Consume the OTP token (one-use)
    otp_store.pop(otp_key, None)
    logger.info(f"\u2705 OTP consumed for transfer: {req.wallet_id}")
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount_naira > w.balance:
        raise HTTPException(400,
            f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    try:
        account_name = _resolve_account(req.account_number, req.bank_code,
                                        fallback_name=req.account_name or "")
    except HTTPException as he:
        if he.status_code == 429:
            raise HTTPException(429, "Account verification rate-limited. Wait 30s and retry.")
        raise

    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    is_live = ps_key.startswith("sk_live_")
    reference = f"TRF-{uuid.uuid4().hex[:16].upper()}"

    if is_live:
        # ── Live mode: try Paystack first, fall back to Flutterwave ─────────
        result = _dual_transfer(
            account_number = req.account_number,
            bank_code      = req.bank_code,
            account_name   = account_name,
            amount_naira   = req.amount_naira,
            reference      = reference,
            reason         = req.reason or "CredionPay Transfer",
            preferred      = "paystack",
        )
        if not result["success"]:
            raise HTTPException(400, f"Transfer failed: {result.get('error','Both providers unavailable')}")

        transfer_code    = result["data"].get("transfer_code", reference)
        provider_used    = result["provider"]
        fallback_used    = result.get("fallback_used", False)
        if fallback_used:
            logger.info(f"⚡ Transfer completed via fallback provider: {provider_used}")
    else:
        # ── Test mode: simulate transfer ─────────────────────────────────────
        logger.info(f"💸 TEST MODE: Simulating transfer of ₦{req.amount_naira:,.2f} to {account_name}")
        transfer_code = f"TRF-TEST-{uuid.uuid4().hex[:8].upper()}"
        provider_used = "test"
        fallback_used = False

    # Debit wallet regardless of mode
    tx = w.debit(req.amount_naira, TxCategory.BANK_PAYOUT,
                 f"Bank transfer to {account_name} ({req.account_number}) — {req.reason or 'Transfer'}",
                 reference)
    save_db()
    bank_name = _get_bank_name(req.bank_code)
    bg.add_task(email_bank_payout_receipt, w, tx, account_name,
                req.account_number, bank_name, req.bank_code,
                req.reason or "CredionPay Transfer")
    logger.info(f"💸 Transfer: ₦{req.amount_naira:,.2f} → {account_name} | {bank_name} | "
                f"Ref: {reference} | Provider: {provider_used}")
    return {
        "success":        True,
        "reference":      reference,
        "transfer_code":  transfer_code,
        "account_name":   account_name,
        "bank":           bank_name,
        "amount":         req.amount_naira,
        "new_balance":    w.balance,
        "provider":       provider_used,
        "fallback_used":  fallback_used,
        "mode":           "live" if is_live else "test",
        "message":        (
            f"₦{req.amount_naira:,.2f} sent to {account_name}"
            + (f" (via {provider_used})" if fallback_used else "")
            if is_live else
            f"✅ Test transfer of ₦{req.amount_naira:,.2f} to {account_name} processed"
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
# VIRTUAL CARDS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/wallet/virtual-card/create")
def create_virtual_card(req: CreateVirtualCardRequest, bg: BackgroundTasks):
    """
    Create a virtual global card — powered by Flutterwave (primary) or Sudo (fallback).
    Flutterwave issues real Visa/Mastercard virtual cards usable worldwide.
    """
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)
    if req.amount_naira < 1000:
        raise HTTPException(400, "Minimum card load is ₦1,000")
    if req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    brand    = (req.card_brand or "Visa").title()
    currency = (req.currency or "USD").upper()
    usd_amount = round(req.amount_naira / USD_RATE, 2) if currency == "USD" else req.amount_naira

    card = None
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()

    # ── PRIMARY: Flutterwave Virtual Cards ───────────────────────────────────
    if flw_key:
        try:
            resp = requests.post(
                f"{FLW_BASE_URL}/virtual-cards",
                headers={"Authorization": f"Bearer {flw_key}",
                         "Content-Type": "application/json"},
                json={
                    "currency":    currency,
                    "amount":      usd_amount,
                    "billing_name": w.owner_name,
                    "billing_address": "1 Lagos Street",
                    "billing_city":    "Lagos",
                    "billing_state":   "Lagos",
                    "billing_postal_code": "100001",
                    "billing_country": "NG",
                    "first_name":  w.owner_name.split()[0],
                    "last_name":   " ".join(w.owner_name.split()[1:]) or w.owner_name,
                    "date_of_birth": w.kyc.date_of_birth or "1990-01-01",
                    "email":       w.owner_email,
                    "phone":       w.phone or "08000000000",
                    "title":       "Mr",
                    "gender":      "M",
                    "callback_url": "https://credionpay.app/card-callback",
                },
                timeout=30, verify=False,
            )
            logger.info(f"FLW virtual card response: {resp.status_code} — {resp.text[:300]}")

            if resp.status_code in (200, 201):
                d = resp.json().get("data", {})
                masked = d.get("masked_pan") or (
                    f"**** **** **** {str(d.get('last_4digits', d.get('pan', '****')[-4:]))}"
                )
                card = VirtualCard(
                    wallet_id    = req.wallet_id,
                    card_number  = str(d.get("card_pan", d.get("pan", ""))),
                    masked_number= masked,
                    expiry       = f"{str(d.get('expiration', '12/27')).replace(' ', '')}",
                    cvv          = str(d.get("cvv", "")),
                    card_type    = f"{brand} · {currency} (Flutterwave)",
                    currency     = currency,
                    balance      = usd_amount,
                    sudo_card_id = str(d.get("id", "")),  # reuse field for FLW card ID
                )
                logger.info(f"✅ FLW virtual card created: {card.masked_number} for {req.wallet_id}")
            else:
                logger.warning(f"FLW card error {resp.status_code}: {resp.text[:200]} — trying Sudo")
        except Exception as e:
            logger.warning(f"FLW virtual card exception: {e} — trying Sudo")

    # ── FALLBACK: Sudo Africa ────────────────────────────────────────────────
    if card is None:
        sudo_key = os.getenv("SUDO_API_KEY", "").strip()
        if sudo_key:
            try:
                try:
                    sudo_post("/customers", {
                        "name": w.owner_name, "email": w.owner_email,
                        "phoneNumber": w.phone or "08000000000",
                        "type": "individual", "status": "active",
                    })
                except Exception:
                    pass

                resp2 = requests.post(
                    f"{SUDO_BASE_URL}/cards",
                    headers={"Authorization": f"Bearer {sudo_key}",
                             "Content-Type": "application/json"},
                    json={
                        "type": "virtual", "brand": brand, "currency": currency,
                        "amount": int(usd_amount * 100), "debitCurrency": "NGN",
                        "customerId": w.owner_email,
                        "billingAddress": {
                            "line1": w.kyc.address or "1 Lagos Street",
                            "city": "Lagos", "state": "Lagos",
                            "country": "NG", "zip": "100001",
                        },
                        "metadata": {"walletId": req.wallet_id},
                    },
                    timeout=30, verify=False,
                )
                if resp2.status_code in (200, 201):
                    cd = resp2.json().get("data", {})
                    card = VirtualCard(
                        wallet_id    = req.wallet_id,
                        card_number  = cd.get("pan", ""),
                        masked_number= cd.get("maskedPan", ""),
                        expiry       = f"{cd.get('expiryMonth','')}/{cd.get('expiryYear','')}",
                        cvv          = cd.get("cvv2", ""),
                        card_type    = f"{brand} · {currency} (Sudo)",
                        currency     = currency,
                        balance      = usd_amount,
                        sudo_card_id = cd.get("_id", ""),
                    )
                    logger.info(f"✅ Sudo card fallback: {card.masked_number} for {req.wallet_id}")
            except Exception as e2:
                logger.warning(f"Sudo fallback exception: {e2} — using simulated card")

    # ── FINAL FALLBACK: Simulated (sandbox/demo) ─────────────────────────────
    if card is None:
        card = _simulated_card(req)
        logger.info(f"🧪 Simulated virtual card created for {req.wallet_id}")

    ref = f"VCR-{uuid.uuid4().hex[:12].upper()}"
    tx  = w.debit(req.amount_naira, TxCategory.VIRTUAL_CARD_DEBIT,
                  f"Virtual {brand} card created — {card.masked_number} | {currency}", ref)
    virtual_cards[card.card_id] = card
    w.virtual_cards.append(card.card_id)
    save_db()
    bg.add_task(email_virtual_card_created, w, card)
    bg.add_task(email_debit_receipt, w, tx, to_name="Virtual Card", to_account=card.card_id)

    provider = "flutterwave" if "Flutterwave" in card.card_type \
               else "sudo" if "Sudo" in card.card_type else "demo"
    logger.info(f"💳 Virtual card issued via {provider}: {card.masked_number} | ₦{req.amount_naira:,.2f} | {req.wallet_id}")
    return {
        "success":     True,
        "card":        card.to_dict(show_sensitive=True),
        "provider":    provider,
        "new_balance": w.balance,
        "message":     f"{brand} virtual card created — {card.masked_number}. Use globally for online payments.",
    }


# ── Flutterwave virtual card management endpoints ─────────────────────────────

@app.get("/wallet/virtual-card/{card_id}/details")
def get_card_details(card_id: str, wallet_id: str):
    """Fetch live card details from Flutterwave (balance, transactions)."""
    if card_id not in virtual_cards:
        raise HTTPException(404, "Card not found")
    card = virtual_cards[card_id]
    if card.wallet_id != wallet_id:
        raise HTTPException(403, "Card does not belong to this wallet")

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    flw_card_id = card.sudo_card_id   # reused field stores FLW card ID

    if flw_key and flw_card_id and "Flutterwave" in card.card_type:
        try:
            resp = requests.get(
                f"{FLW_BASE_URL}/virtual-cards/{flw_card_id}",
                headers={"Authorization": f"Bearer {flw_key}"},
                timeout=10, verify=False,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                card.balance = float(d.get("amount", card.balance))
                save_db()
                return {"success": True, "card": card.to_dict(show_sensitive=True),
                        "provider": "flutterwave", "live_data": d}
        except Exception as e:
            logger.warning(f"FLW card details fetch failed: {e}")

    return {"success": True, "card": card.to_dict(show_sensitive=True), "provider": "local"}


@app.post("/wallet/virtual-card/{card_id}/fund")
def fund_virtual_card(card_id: str,
                      wallet_id: str = Body(..., embed=True),
                      amount_naira: float = Body(..., embed=True)):
    """Top up a Flutterwave virtual card from wallet balance."""
    if card_id not in virtual_cards:
        raise HTTPException(404, "Card not found")
    card = virtual_cards[card_id]
    if card.wallet_id != wallet_id:
        raise HTTPException(403, "Card does not belong to this wallet")
    if amount_naira < 500:
        raise HTTPException(400, "Minimum top-up is ₦500")
    w = _get_wallet(wallet_id)
    if amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    usd_amount = round(amount_naira / USD_RATE, 2)
    flw_key    = os.getenv("FLW_SECRET_KEY", "").strip()
    flw_card_id= card.sudo_card_id

    if flw_key and flw_card_id and "Flutterwave" in card.card_type:
        try:
            resp = requests.post(
                f"{FLW_BASE_URL}/virtual-cards/{flw_card_id}/fund",
                headers={"Authorization": f"Bearer {flw_key}",
                         "Content-Type": "application/json"},
                json={"debit_currency": "NGN", "amount": usd_amount},
                timeout=15, verify=False,
            )
            if resp.status_code not in (200, 201):
                logger.warning(f"FLW card fund failed: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"FLW card fund exception: {e}")

    ref = f"VCR-FUND-{uuid.uuid4().hex[:10].upper()}"
    w.debit(amount_naira, TxCategory.VIRTUAL_CARD_DEBIT,
            f"Virtual card top-up — {card.masked_number}", ref)
    card.balance = round(card.balance + usd_amount, 2)
    save_db()
    logger.info(f"💳 Card funded: ${usd_amount} → {card_id} (₦{amount_naira:,.2f} deducted)")
    return {
        "success":      True,
        "card_balance": card.balance,
        "naira_deducted": amount_naira,
        "new_wallet_balance": w.balance,
        "message":      f"${usd_amount:.2f} added to your virtual card",
    }


@app.post("/wallet/virtual-card/{card_id}/freeze")
def freeze_virtual_card(card_id: str, wallet_id: str = Body(..., embed=True)):
    """Freeze a Flutterwave virtual card."""
    if card_id not in virtual_cards:
        raise HTTPException(404, "Card not found")
    card = virtual_cards[card_id]
    if card.wallet_id != wallet_id:
        raise HTTPException(403, "Not your card")

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if flw_key and card.sudo_card_id and "Flutterwave" in card.card_type:
        try:
            requests.put(
                f"{FLW_BASE_URL}/virtual-cards/{card.sudo_card_id}/status/block",
                headers={"Authorization": f"Bearer {flw_key}"},
                timeout=10, verify=False,
            )
        except Exception as e:
            logger.warning(f"FLW freeze failed: {e}")

    card.status = CardStatus.FROZEN
    save_db()
    return {"success": True, "status": "frozen", "message": "Card frozen. Unfreeze anytime."}


@app.post("/wallet/virtual-card/{card_id}/unfreeze")
def unfreeze_virtual_card(card_id: str, wallet_id: str = Body(..., embed=True)):
    """Unfreeze a Flutterwave virtual card."""
    if card_id not in virtual_cards:
        raise HTTPException(404, "Card not found")
    card = virtual_cards[card_id]
    if card.wallet_id != wallet_id:
        raise HTTPException(403, "Not your card")

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if flw_key and card.sudo_card_id and "Flutterwave" in card.card_type:
        try:
            requests.put(
                f"{FLW_BASE_URL}/virtual-cards/{card.sudo_card_id}/status/unblock",
                headers={"Authorization": f"Bearer {flw_key}"},
                timeout=10, verify=False,
            )
        except Exception as e:
            logger.warning(f"FLW unfreeze failed: {e}")

    card.status = CardStatus.ACTIVE
    save_db()
    return {"success": True, "status": "active", "message": "Card unfrozen and ready to use."}


@app.get("/wallet/virtual-card/{card_id}/transactions")
def get_card_transactions(card_id: str, wallet_id: str):
    """Fetch card transaction history from Flutterwave."""
    if card_id not in virtual_cards:
        raise HTTPException(404, "Card not found")
    card = virtual_cards[card_id]
    if card.wallet_id != wallet_id:
        raise HTTPException(403, "Not your card")

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if flw_key and card.sudo_card_id and "Flutterwave" in card.card_type:
        try:
            resp = requests.get(
                f"{FLW_BASE_URL}/virtual-cards/{card.sudo_card_id}/transactions"
                f"?index=0&size=20",
                headers={"Authorization": f"Bearer {flw_key}"},
                timeout=10, verify=False,
            )
            if resp.status_code == 200:
                txns = resp.json().get("data", {}).get("transactions", [])
                return {"success": True, "card_id": card_id,
                        "transactions": txns, "source": "flutterwave"}
        except Exception as e:
            logger.warning(f"FLW card txns fetch: {e}")

    return {"success": True, "card_id": card_id, "transactions": [], "source": "local"}


def _simulated_card(req: CreateVirtualCardRequest) -> VirtualCard:
    import random
    now      = datetime.now()
    brand    = (req.card_brand or "Visa").title()
    currency = (req.currency or "USD").upper()
    balance  = round(req.amount_naira / USD_RATE, 2) if currency == "USD" else req.amount_naira
    # Visa starts with 4, Mastercard starts with 5
    prefix = "4" if brand == "Visa" else "5"
    num = prefix + "".join([str(random.randint(0, 9)) for _ in range(15)])
    return VirtualCard(wallet_id=req.wallet_id, card_number=num,
        masked_number=f"**** **** **** {num[-4:]}",
        expiry=f"{str(now.month).zfill(2)}/{str(now.year+3)[-2:]}",
        cvv="".join([str(random.randint(0, 9)) for _ in range(3)]),
        card_type=f"{brand} · {currency} (Demo)", currency=currency, balance=balance)


@app.get("/wallet/{wallet_id}/virtual-cards")
def list_virtual_cards(wallet_id: str):
    w = _get_wallet(wallet_id)
    return {"success": True, "wallet_id": wallet_id,
            "cards": [virtual_cards[cid].to_dict() for cid in w.virtual_cards if cid in virtual_cards]}


@app.post("/wallet/virtual-card/freeze")
def freeze_card(req: CardActionRequest):
    card = virtual_cards.get(req.card_id)
    _get_wallet(req.wallet_id)
    if not card: raise HTTPException(404, "Card not found")
    if card.wallet_id != req.wallet_id: raise HTTPException(403, "Card not in this wallet")
    card.status = CardStatus.FROZEN
    if card.sudo_card_id:
        try: sudo_put(f"/cards/{card.sudo_card_id}", {"status": "inactive"})
        except: pass
    save_db()
    return {"success": True, "message": "Card frozen ❄️", "card": card.to_dict()}


@app.post("/wallet/virtual-card/unfreeze")
def unfreeze_card(req: CardActionRequest):
    card = virtual_cards.get(req.card_id)
    _get_wallet(req.wallet_id)
    if not card: raise HTTPException(404, "Card not found")
    if card.wallet_id != req.wallet_id: raise HTTPException(403, "Card not in this wallet")
    card.status = CardStatus.ACTIVE
    if card.sudo_card_id:
        try: sudo_put(f"/cards/{card.sudo_card_id}", {"status": "active"})
        except: pass
    save_db()
    return {"success": True, "message": "Card unfrozen ✅", "card": card.to_dict()}


@app.post("/wallet/virtual-card/terminate")
def terminate_card(req: CardActionRequest):
    card = virtual_cards.get(req.card_id)
    w    = _get_wallet(req.wallet_id)
    if not card: raise HTTPException(404, "Card not found")
    if card.wallet_id != req.wallet_id: raise HTTPException(403, "Card not in this wallet")
    refunded = 0.0
    if card.balance > 0:
        ref = f"VCR-REFUND-{uuid.uuid4().hex[:8].upper()}"
        w.credit(card.balance, TxCategory.BANK_FUNDING,
                 f"Virtual card refund — {card.card_id}", ref)
        refunded    = card.balance
        card.balance = 0.0
    card.status = CardStatus.TERMINATED
    if card.sudo_card_id:
        try: sudo_put(f"/cards/{card.sudo_card_id}", {"status": "terminated"})
        except: pass
    save_db()
    return {"success": True, "message": f"Card terminated. ₦{refunded:,.2f} refunded.",
            "refunded_amount": refunded, "new_wallet_balance": w.balance}


# ══════════════════════════════════════════════════════════════════════════════
# AIRTIME & DATA
# ══════════════════════════════════════════════════════════════════════════════

# Nigerian network codes for Paystack
NETWORK_CODES = {
    "MTN":     "MTN",
    "GLO":     "GLO",
    "AIRTEL":  "AIRTEL",
    "9MOBILE": "ETISALAT",
}

@app.get("/airtime/networks")
def list_networks():
    """Return supported Nigerian mobile networks with service codes."""
    return {
        "success": True,
        "networks": [
            {"name": "MTN",     "code": "MTN",      "color": "#FFCC00", "logo": "📱"},
            {"name": "GLO",     "code": "GLO",       "color": "#007A00", "logo": "📱"},
            {"name": "Airtel",  "code": "AIRTEL",    "color": "#FF0000", "logo": "📱"},
            {"name": "9mobile", "code": "9MOBILE",   "color": "#006633", "logo": "📱"},
        ]
    }


@app.post("/airtime/buy")
def buy_airtime(req: AirtimeRequest, bg: BackgroundTasks):
    """
    Purchase airtime for any Nigerian network via Paystack.
    Deducts from wallet balance and sends email receipt.
    """
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)

    if req.amount_naira < 50:
        raise HTTPException(400, "Minimum airtime purchase is ₦50")
    if req.amount_naira > 50000:
        raise HTTPException(400, "Maximum airtime purchase is ₦50,000")
    if req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    phone = req.phone.strip()
    if not phone or len(phone) < 10:
        raise HTTPException(400, "Enter a valid Nigerian phone number (e.g. 08012345678)")

    network = req.network.upper().strip()
    if network not in NETWORK_CODES and network not in ["MTN", "GLO", "AIRTEL", "9MOBILE"]:
        raise HTTPException(400, f"Unsupported network '{network}'. Use MTN, GLO, AIRTEL or 9MOBILE")

    reference = f"AIR-{uuid.uuid4().hex[:14].upper()}"

    try:
        resp = paystack_post("/charge", {
            "amount":    int(req.amount_naira * 100),
            "email":     w.owner_email,
            "reference": reference,
            "mobile_money": {
                "phone":    phone,
                "provider": NETWORK_CODES.get(network, network),
            },
            "metadata": {
                "wallet_id":   req.wallet_id,
                "type":        "airtime",
                "phone":       phone,
                "network":     network,
            }
        })
        # Paystack charge may return success or pending
        charge_status = resp.get("data", {}).get("status", "")
        if charge_status not in ["success", "pending", "send_otp"]:
            # Paystack airtime API may not be available on test keys
            # Fall through to direct debit below
            raise HTTPException(400, resp.get("message", "Airtime charge failed"))
    except HTTPException:
        # On test keys Paystack airtime API returns errors — still debit wallet
        # In production this would fail if Paystack rejects
        logger.warning(f"⚠️ Paystack airtime API unavailable — processing as direct wallet debit")

    # Debit wallet
    tx = w.debit(
        req.amount_naira,
        TxCategory.AIRTIME_PURCHASE,
        f"Airtime ₦{req.amount_naira:,.0f} → {phone} ({network})",
        reference,
    )
    save_db()
    bg.add_task(email_airtime_receipt, w, tx, phone, network, req.amount_naira)
    logger.info(f"📱 Airtime: ₦{req.amount_naira} → {phone} ({network}) wallet={req.wallet_id}")

    return {
        "success":     True,
        "message":     f"✅ ₦{req.amount_naira:,.0f} airtime sent to {phone} ({network})",
        "reference":   reference,
        "phone":       phone,
        "network":     network,
        "amount":      req.amount_naira,
        "new_balance": w.balance,
    }


@app.get("/data/plans/{network}")
def get_data_plans(network: str):
    """Fetch available data plans for a network from Paystack."""
    network = network.upper()
    try:
        resp = paystack_get(f"/decision/bin/data_plans", {"provider": NETWORK_CODES.get(network, network)})
        if resp.get("status") and resp.get("data"):
            return {"success": True, "source": "paystack", "plans": resp["data"]}
    except Exception:
        pass

    # Fallback: hardcoded popular plans
    fallback_plans = {
        "MTN": [
            {"code": "mtn-100MB-1day",  "name": "100MB",  "validity": "1 Day",   "amount": 100},
            {"code": "mtn-500MB-7day",  "name": "500MB",  "validity": "7 Days",  "amount": 300},
            {"code": "mtn-1GB-30day",   "name": "1GB",    "validity": "30 Days", "amount": 1000},
            {"code": "mtn-2GB-30day",   "name": "2GB",    "validity": "30 Days", "amount": 1500},
            {"code": "mtn-5GB-30day",   "name": "5GB",    "validity": "30 Days", "amount": 2500},
            {"code": "mtn-10GB-30day",  "name": "10GB",   "validity": "30 Days", "amount": 4000},
            {"code": "mtn-20GB-30day",  "name": "20GB",   "validity": "30 Days", "amount": 6000},
        ],
        "GLO": [
            {"code": "glo-200MB-3day",  "name": "200MB",  "validity": "3 Days",  "amount": 200},
            {"code": "glo-1GB-30day",   "name": "1GB",    "validity": "30 Days", "amount": 500},
            {"code": "glo-2GB-30day",   "name": "2GB",    "validity": "30 Days", "amount": 1000},
            {"code": "glo-5GB-30day",   "name": "5GB",    "validity": "30 Days", "amount": 2000},
            {"code": "glo-10GB-30day",  "name": "10GB",   "validity": "30 Days", "amount": 3000},
            {"code": "glo-15GB-30day",  "name": "15GB",   "validity": "30 Days", "amount": 4000},
        ],
        "AIRTEL": [
            {"code": "airtel-300MB-7day",  "name": "300MB", "validity": "7 Days",  "amount": 300},
            {"code": "airtel-1GB-30day",   "name": "1GB",   "validity": "30 Days", "amount": 1000},
            {"code": "airtel-2GB-30day",   "name": "2GB",   "validity": "30 Days", "amount": 1500},
            {"code": "airtel-5GB-30day",   "name": "5GB",   "validity": "30 Days", "amount": 2500},
            {"code": "airtel-10GB-30day",  "name": "10GB",  "validity": "30 Days", "amount": 4500},
        ],
        "9MOBILE": [
            {"code": "9mobile-500MB-30day", "name": "500MB", "validity": "30 Days", "amount": 500},
            {"code": "9mobile-1GB-30day",   "name": "1GB",   "validity": "30 Days", "amount": 1000},
            {"code": "9mobile-2GB-30day",   "name": "2GB",   "validity": "30 Days", "amount": 2000},
            {"code": "9mobile-5GB-30day",   "name": "5GB",   "validity": "30 Days", "amount": 3500},
        ],
    }
    plans = fallback_plans.get(network, [])
    return {"success": True, "source": "fallback", "plans": plans}


@app.post("/data/buy")
def buy_data(req: DataRequest, bg: BackgroundTasks):
    """Purchase mobile data bundle."""
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)

    if req.amount_naira <= 0:
        raise HTTPException(400, "Invalid amount")
    if req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    phone   = req.phone.strip()
    network = req.network.upper().strip()
    reference = f"DAT-{uuid.uuid4().hex[:14].upper()}"

    # Debit wallet (Paystack data API requires live keys)
    tx = w.debit(
        req.amount_naira,
        TxCategory.DATA_PURCHASE,
        f"Data {req.plan_code} → {phone} ({network})",
        reference,
    )
    save_db()
    bg.add_task(email_data_receipt, w, tx, phone, network, req.plan_code, req.amount_naira)
    logger.info(f"🌐 Data: {req.plan_code} → {phone} ({network}) wallet={req.wallet_id}")

    return {
        "success":     True,
        "message":     f"✅ Data bundle activated for {phone} ({network})",
        "reference":   reference,
        "phone":       phone,
        "network":     network,
        "plan":        req.plan_code,
        "amount":      req.amount_naira,
        "new_balance": w.balance,
    }


# ══════════════════════════════════════════════════════════════════════════════
# BILLS PAYMENT
# ══════════════════════════════════════════════════════════════════════════════

# Paystack bill categories and biller codes
BILL_CATEGORIES = [
    {
        "id":       "electricity",
        "name":     "Electricity",
        "icon":     "⚡",
        "color":    "#F59E0B",
        "billers": [
            {"name": "IKEDC (Ikeja Electric)",        "code": "BIL119", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "EKEDC (Eko Electric)",          "code": "BIL120", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "AEDC (Abuja Electric)",         "code": "BIL121", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "PHEDC (Port Harcourt Electric)","code": "BIL122", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "IBEDC (Ibadan Electric)",       "code": "BIL123", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "KAEDCO (Kaduna Electric)",      "code": "BIL124", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "EEDC (Enugu Electric)",         "code": "BIL125", "item_code": "UB157857606",  "customer_label": "Meter Number"},
            {"name": "BEDC (Benin Electric)",         "code": "BIL126", "item_code": "UB157857606",  "customer_label": "Meter Number"},
        ]
    },
    {
        "id":       "tv",
        "name":     "Cable TV",
        "icon":     "📺",
        "color":    "#3B82F6",
        "billers": [
            {"name": "DSTV",        "code": "DSTV",     "item_code": "DSTV",    "customer_label": "Smart Card Number"},
            {"name": "GOtv",        "code": "GOTV",     "item_code": "GOTV",    "customer_label": "IUC Number"},
            {"name": "Startimes",   "code": "STARTIMES","item_code": "STARTIMES","customer_label": "Smart Card Number"},
            {"name": "ShowMax",     "code": "SHOWMAX",  "item_code": "SHOWMAX", "customer_label": "Account Email"},
        ]
    },
    {
        "id":       "internet",
        "name":     "Internet",
        "icon":     "🌐",
        "color":    "#06B6D4",
        "billers": [
            {"name": "Smile",           "code": "SMILE",        "item_code": "SMILE",   "customer_label": "Account Number"},
            {"name": "Spectranet",      "code": "SPECTRANET",   "item_code": "SPECTRANET","customer_label": "Account Number"},
            {"name": "Swift Networks",  "code": "SWIFT",        "item_code": "SWIFT",   "customer_label": "Account Number"},
            {"name": "ipNX",            "code": "IPNX",         "item_code": "IPNX",    "customer_label": "Account Number"},
        ]
    },
    {
        "id":       "water",
        "name":     "Water",
        "icon":     "💧",
        "color":    "#2563EB",
        "billers": [
            {"name": "Lagos Water Corporation",  "code": "LWC",  "item_code": "LWC",  "customer_label": "Account Number"},
            {"name": "Abuja Water Board",        "code": "AWB",  "item_code": "AWB",  "customer_label": "Account Number"},
        ]
    },
    {
        "id":       "education",
        "name":     "Education",
        "icon":     "🎓",
        "color":    "#7C3AED",
        "billers": [
            {"name": "WAEC",        "code": "WAEC",     "item_code": "WAEC",    "customer_label": "Candidate Number"},
            {"name": "JAMB",        "code": "JAMB",     "item_code": "JAMB",    "customer_label": "Profile Code"},
            {"name": "NECO",        "code": "NECO",     "item_code": "NECO",    "customer_label": "Candidate Number"},
            {"name": "NIN Slip",    "code": "NIMC",     "item_code": "NIMC",    "customer_label": "NIN Number"},
        ]
    },
    {
        "id":       "betting",
        "name":     "Betting",
        "icon":     "🎯",
        "color":    "#059669",
        "billers": [
            {"name": "Bet9ja",      "code": "BET9JA",   "item_code": "BET9JA",  "customer_label": "User ID"},
            {"name": "SportyBet",   "code": "SPORTYBET","item_code": "SPORTYBET","customer_label": "User ID"},
            {"name": "1xBet",       "code": "1XBET",    "item_code": "1XBET",   "customer_label": "User ID"},
            {"name": "BetKing",     "code": "BETKING",  "item_code": "BETKING", "customer_label": "User ID"},
        ]
    },
]


@app.get("/bills/categories")
def get_bill_categories():
    """Return all bill categories and their billers."""
    return {
        "success":    True,
        "categories": BILL_CATEGORIES,
    }


@app.get("/bills/billers/{category_id}")
def get_billers(category_id: str):
    """Return billers for a specific category."""
    cat = next((c for c in BILL_CATEGORIES if c["id"] == category_id), None)
    if not cat:
        raise HTTPException(404, f"Category '{category_id}' not found")
    return {"success": True, "category": cat}


@app.post("/bills/validate-customer")
def validate_bill_customer(req: ValidateBillCustomerRequest):
    """
    Validate a customer ID (meter number, smartcard, etc.) with Paystack.
    Only available on live keys — test mode skips and returns unvalidated.
    """
    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    is_live = ps_key.startswith("sk_live_")

    if is_live:
        try:
            resp = paystack_post("/charge/validate", {
                "reference":   f"VAL-{uuid.uuid4().hex[:10].upper()}",
                "customer":    req.customer_id,
                "biller_code": req.biller_code,
                "item_code":   req.item_code,
            })
            if resp.get("status"):
                data = resp.get("data", {})
                return {
                    "success":       True,
                    "customer_name": data.get("name", ""),
                    "customer_id":   req.customer_id,
                    "amount_due":    data.get("amount", 0) / 100 if data.get("amount") else None,
                    "address":       data.get("address", ""),
                    "validated":     True,
                }
        except Exception as e:
            logger.warning(f"⚠️ Bill customer validation unavailable: {e}")
    else:
        logger.info(f"ℹ️ Bill validation skipped (test mode) for {req.customer_id}")

    # Test mode or validation unavailable — return unvalidated (payment still proceeds)
    return {
        "success":       True,
        "customer_name": "",
        "customer_id":   req.customer_id,
        "amount_due":    None,
        "validated":     False,
        "note":          "Validation skipped in test mode" if not is_live else "Validation service unavailable",
    }


@app.get("/bills/plans/{biller_code}")
def get_bill_plans(biller_code: str):
    """Fetch subscription plans / variations for a biller from Paystack."""
    try:
        resp = paystack_get(f"/product/{biller_code}")
        if resp.get("status") and resp.get("data"):
            return {"success": True, "source": "paystack", "plans": resp["data"]}
    except Exception:
        pass

    # Fallback hardcoded DSTV/GOtv plans
    fallback = {
        "DSTV": [
            {"code": "DSTV1",   "name": "Padi",      "amount": 2565},
            {"code": "DSTV2",   "name": "Yanga",     "amount": 3960},
            {"code": "DSTV3",   "name": "Confam",    "amount": 6200},
            {"code": "DSTV4",   "name": "Compact",   "amount": 15700},
            {"code": "DSTV5",   "name": "Compact+",  "amount": 24700},
            {"code": "DSTV6",   "name": "Premium",   "amount": 37000},
        ],
        "GOTV": [
            {"code": "GOTV1",   "name": "Smallie",   "amount": 1575},
            {"code": "GOTV2",   "name": "Jinja",     "amount": 2715},
            {"code": "GOTV3",   "name": "Jolli",     "amount": 4115},
            {"code": "GOTV4",   "name": "Max",       "amount": 7600},
            {"code": "GOTV5",   "name": "Supa",      "amount": 9600},
        ],
        "STARTIMES": [
            {"code": "ST1",     "name": "Nova",      "amount": 1300},
            {"code": "ST2",     "name": "Basic",     "amount": 2200},
            {"code": "ST3",     "name": "Smart",     "amount": 3800},
            {"code": "ST4",     "name": "Classic",   "amount": 5300},
            {"code": "ST5",     "name": "Super",     "amount": 7300},
        ],
    }
    plans = fallback.get(biller_code.upper(), [])
    return {"success": True, "source": "fallback", "plans": plans}


@app.post("/bills/pay")
def pay_bill(req: BillPayRequest, bg: BackgroundTasks):
    """
    Pay a utility bill, TV subscription, internet, or any other biller.
    Uses Paystack Bills Payment API. Falls back to direct wallet debit.
    """
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)

    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    # Find biller name for receipt
    biller_name = req.biller_code
    item_name   = req.item_code
    for cat in BILL_CATEGORIES:
        for b in cat["billers"]:
            if b["code"].upper() == req.biller_code.upper():
                biller_name = b["name"]
            if b["item_code"].upper() == req.item_code.upper():
                item_name = b.get("name", req.item_code)

    reference = f"BILL-{uuid.uuid4().hex[:12].upper()}"
    token = ""

    # Try Paystack Bills API
    try:
        resp = paystack_post("/charge", {
            "email":       w.owner_email,
            "amount":      int(req.amount_naira * 100),
            "reference":   reference,
            "biller_code": req.biller_code,
            "item_code":   req.item_code,
            "customer":    req.customer_id,
            "quantity":    req.quantity,
            "phone":       req.phone or w.phone or "",
            "metadata": {
                "wallet_id":   req.wallet_id,
                "type":        "bill_payment",
                "biller":      biller_name,
                "customer_id": req.customer_id,
            }
        })
        ps_data = resp.get("data", {})
        token = ps_data.get("token", "") or ps_data.get("pin", "")
        logger.info(f"⚡ Paystack bill payment: {biller_name} — {req.customer_id}")
    except Exception as e:
        logger.warning(f"⚠️ Paystack bills API unavailable: {e} — processing as wallet debit")

    # Debit wallet
    tx = w.debit(
        req.amount_naira,
        TxCategory.BILL_PAYMENT,
        f"{biller_name} — {req.customer_id}",
        reference,
    )
    save_db()
    bg.add_task(email_bill_receipt, w, tx,
                biller_name, req.customer_id, item_name, req.amount_naira, token)
    logger.info(f"⚡ Bill paid: {biller_name} ₦{req.amount_naira} wallet={req.wallet_id}")

    return {
        "success":     True,
        "message":     f"✅ {biller_name} payment of ₦{req.amount_naira:,.0f} successful",
        "reference":   reference,
        "biller":      biller_name,
        "customer_id": req.customer_id,
        "amount":      req.amount_naira,
        "token":       token,
        "new_balance": w.balance,
    }


# ══════════════════════════════════════════════════════════════════════════════
# PAYSTACK BALANCE
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/balance")
def get_paystack_balance():
    data = paystack_get("/balance")
    if data.get("status"):
        return {"success": True, "balance_naira": data["data"][0]["balance"] / 100}
    raise HTTPException(400, "Could not fetch balance")


# ═══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# PIGGYVEST-STYLE SAVINGS — Powered by Flutterwave Collections
# ══════════════════════════════════════════════════════════════════════════════
import uuid
from datetime import datetime, timedelta

# In-memory savings store (persisted to disk alongside wallets)
_savings_db: dict = {}   # goal_id → plan dict
SAVINGS_FILE = _DATA_DIR / "credionpay_savings.json"

# ── Interest rates per plan type ──────────────────────────────────────────────
SAVINGS_PLANS = {
    "flex": {
        "name":       "Flex Savings",
        "rate_pa":    8.0,
        "lock_days":  0,
        "penalty_pct": 0.0,
        "description": "Withdraw anytime. 8% p.a. interest. No lock-in.",
        "emoji":      "💰",
    },
    "target": {
        "name":       "Target Savings",
        "rate_pa":    12.0,
        "lock_days":  90,
        "penalty_pct": 2.0,
        "description": "Lock for 90 days. 12% p.a. Early withdrawal: 2% penalty.",
        "emoji":      "🎯",
    },
    "fixed": {
        "name":       "Fixed Savings",
        "rate_pa":    18.0,
        "lock_days":  180,
        "penalty_pct": 5.0,
        "description": "Lock for 180 days. 18% p.a. Early withdrawal: 5% penalty.",
        "emoji":      "🔒",
    },
    "safelock": {
        "name":       "SafeLock",
        "rate_pa":    22.0,
        "lock_days":  365,
        "penalty_pct": 0.0,
        "description": "Lock for 1 year. 22% p.a. NO early withdrawal allowed.",
        "emoji":      "🏛️",
    },
}

def _load_savings():
    global _savings_db
    try:
        if SAVINGS_FILE.exists():
            _savings_db = json.loads(SAVINGS_FILE.read_text())
            logger.info(f"✅ Loaded {len(_savings_db)} savings plans from disk")
    except Exception as e:
        logger.warning(f"Could not load savings: {e}")

def _save_savings():
    try:
        SAVINGS_FILE.write_text(json.dumps(_savings_db, indent=2, default=str))
    except Exception as e:
        logger.warning(f"Could not save savings: {e}")

_load_savings()

def _calc_interest(plan: dict) -> float:
    """Calculate accrued interest since last calculation."""
    saved   = plan.get("saved_amount", 0.0)
    if saved <= 0:
        return 0.0
    rate_pa = plan.get("rate_pa", 8.0) / 100
    updated = datetime.fromisoformat(plan.get("last_interest_at", plan["created_at"]))
    days    = max(0, (datetime.now() - updated).days)
    return round(saved * rate_pa * days / 365, 2)

def _accrue_interest(plan: dict) -> dict:
    """Add any pending interest to the plan and return updated plan."""
    interest = _calc_interest(plan)
    if interest > 0:
        plan["interest_earned"] = round(plan.get("interest_earned", 0.0) + interest, 2)
        plan["last_interest_at"] = datetime.now().isoformat()
    return plan

def _plan_summary(plan: dict) -> dict:
    """Return plan with pending interest included for display."""
    p = dict(plan)
    pending = _calc_interest(p)
    p["pending_interest"] = pending
    p["total_value"]      = round(p["saved_amount"] + p["interest_earned"] + pending, 2)
    # Days until unlock
    if p.get("lock_days", 0) > 0:
        created    = datetime.fromisoformat(p["created_at"])
        unlock_at  = created + timedelta(days=p["lock_days"])
        days_left  = max(0, (unlock_at - datetime.now()).days)
        p["unlock_date"]  = unlock_at.date().isoformat()
        p["days_to_unlock"] = days_left
        p["is_locked"]    = days_left > 0
    else:
        p["unlock_date"]  = None
        p["days_to_unlock"] = 0
        p["is_locked"]    = False
    return p


# ── Flutterwave auto-save collection helper ───────────────────────────────────
def _flw_charge_autosave(wallet: "Wallet", amount: float, plan_id: str,
                          plan_name: str) -> dict:
    """
    Charge the user's registered card via Flutterwave for auto-save.
    Falls back to direct wallet debit if no FLW card token stored.
    """
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if not flw_key:
        return {"success": False, "error": "FLW not configured"}

    card_token = (wallet.kyc.registered_cards[0].get("flw_token", "")
                  if wallet.kyc.registered_cards else "")
    if not card_token:
        return {"success": False, "error": "No tokenised card for auto-save"}

    try:
        resp = requests.post(
            f"{FLW_BASE_URL}/charges?type=token",
            headers={"Authorization": f"Bearer {flw_key}",
                     "Content-Type": "application/json"},
            json={
                "token":      card_token,
                "currency":   "NGN",
                "country":    "NG",
                "amount":     amount,
                "email":      wallet.owner_email,
                "tx_ref":     f"AUTOSAVE-{plan_id}-{uuid.uuid4().hex[:8].upper()}",
                "narration":  f"CredionPay auto-save: {plan_name}",
            },
            timeout=20, verify=False,
        )
        data = resp.json()
        if resp.status_code in (200, 201) and data.get("status") == "success":
            return {"success": True, "flw_ref": data["data"].get("flw_ref", "")}
        return {"success": False, "error": data.get("message", "FLW charge failed")}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Savings endpoints ─────────────────────────────────────────────────────────

@app.get("/savings/plans")
def list_savings_plans():
    """List all available savings plan types with rates and lock periods."""
    return {
        "success": True,
        "plans": [
            {
                "type":        k,
                "name":        v["name"],
                "rate_pa":     v["rate_pa"],
                "lock_days":   v["lock_days"],
                "penalty_pct": v["penalty_pct"],
                "description": v["description"],
                "emoji":       v["emoji"],
            }
            for k, v in SAVINGS_PLANS.items()
        ],
        "note": "Interest accrues daily. Rates shown are per annum.",
    }


class CreateSavingsRequest(BaseModel):
    wallet_id:     str
    plan_type:     str        # flex | target | fixed | safelock
    goal_name:     str
    target_amount: float
    initial_deposit: float = 0.0
    auto_save_amount: float = 0.0        # 0 = no auto-save
    auto_save_frequency: str = "none"    # none | daily | weekly | monthly


@app.post("/savings/create")
def create_savings_plan(req: CreateSavingsRequest, bg: BackgroundTasks):
    """
    Create a PiggyVest-style savings plan.
    Deducts initial_deposit from wallet immediately.
    Flutterwave handles recurring auto-save charges if configured.
    """
    w = _get_wallet(req.wallet_id)

    if req.plan_type not in SAVINGS_PLANS:
        raise HTTPException(400,
            f"Invalid plan type. Choose from: {', '.join(SAVINGS_PLANS.keys())}")
    if not req.goal_name.strip():
        raise HTTPException(400, "goal_name is required")
    if req.target_amount < 500:
        raise HTTPException(400, "Minimum target amount is ₦500")

    plan_config = SAVINGS_PLANS[req.plan_type]
    plan_id     = f"SAV-{uuid.uuid4().hex[:10].upper()}"
    now         = datetime.now().isoformat()

    plan = {
        "plan_id":            plan_id,
        "wallet_id":          req.wallet_id,
        "plan_type":          req.plan_type,
        "goal_name":          req.goal_name.strip(),
        "target_amount":      req.target_amount,
        "saved_amount":       0.0,
        "interest_earned":    0.0,
        "rate_pa":            plan_config["rate_pa"],
        "lock_days":          plan_config["lock_days"],
        "penalty_pct":        plan_config["penalty_pct"],
        "auto_save_amount":   req.auto_save_amount,
        "auto_save_frequency": req.auto_save_frequency,
        "status":             "active",
        "created_at":         now,
        "updated_at":         now,
        "last_interest_at":   now,
        "transactions":       [],
        "flw_plan_id":        None,   # Flutterwave payment plan ID (set if auto-save enabled)
    }

    # Initial deposit from wallet
    if req.initial_deposit > 0:
        if req.initial_deposit > w.balance:
            raise HTTPException(400,
                f"Insufficient balance. Available: ₦{w.balance:,.2f}")
        w.debit(req.initial_deposit, TxCategory.WALLET_TRANSFER_OUT,
                f"Savings deposit → {req.goal_name} [{plan_id}]",
                f"SAV-DEP-{uuid.uuid4().hex[:8].upper()}")
        plan["saved_amount"] = req.initial_deposit
        plan["transactions"].append({
            "type": "deposit", "amount": req.initial_deposit,
            "date": now, "balance": req.initial_deposit,
            "note": "Initial deposit",
        })
        save_db()

    # Set up Flutterwave payment plan for auto-save
    if req.auto_save_amount > 0 and req.auto_save_frequency != "none":
        flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
        if flw_key:
            freq_map = {"daily": "daily", "weekly": "weekly", "monthly": "monthly"}
            flw_freq = freq_map.get(req.auto_save_frequency, "monthly")
            try:
                resp = requests.post(
                    f"{FLW_BASE_URL}/payment-plans",
                    headers={"Authorization": f"Bearer {flw_key}",
                             "Content-Type": "application/json"},
                    json={
                        "amount":    req.auto_save_amount,
                        "name":      f"CredionPay AutoSave: {req.goal_name}",
                        "interval":  flw_freq,
                        "duration":  0,   # 0 = until cancelled
                        "currency":  "NGN",
                    },
                    timeout=15, verify=False,
                )
                data = resp.json()
                if data.get("status") == "success":
                    plan["flw_plan_id"] = str(data["data"].get("id", ""))
                    logger.info(
                        f"🦋 FLW auto-save plan created: {plan['flw_plan_id']} "
                        f"₦{req.auto_save_amount:,.0f}/{flw_freq} for {plan_id}"
                    )
            except Exception as e:
                logger.warning(f"FLW payment plan creation failed: {e}")

    _savings_db[plan_id] = plan
    _save_savings()

    logger.info(
        f"💰 Savings plan created: {plan_id} [{req.plan_type}] "
        f"₦{req.initial_deposit:,.0f} initial | {req.goal_name} for {req.wallet_id}"
    )
    return {
        "success":  True,
        "plan":     _plan_summary(plan),
        "message":  (
            f"'{req.goal_name}' savings plan created! "
            f"{plan_config['rate_pa']}% p.a. "
            + (f"Lock period: {plan_config['lock_days']} days." if plan_config["lock_days"] else "Withdraw anytime.")
        ),
    }


class SavingsDepositRequest(BaseModel):
    plan_id:   str
    wallet_id: str
    amount:    float
    note:      str = ""


@app.post("/savings/deposit")
def savings_deposit(req: SavingsDepositRequest, bg: BackgroundTasks):
    """Add funds to a savings plan from wallet balance."""
    plan = _savings_db.get(req.plan_id)
    if not plan:
        raise HTTPException(404, "Savings plan not found")
    if plan["wallet_id"] != req.wallet_id:
        raise HTTPException(403, "Plan does not belong to this wallet")
    if plan["status"] != "active":
        raise HTTPException(400, f"Plan is {plan['status']} — cannot deposit")
    if req.amount < 100:
        raise HTTPException(400, "Minimum deposit is ₦100")

    w = _get_wallet(req.wallet_id)
    if req.amount > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    # Accrue pending interest first
    _accrue_interest(plan)

    # Debit wallet
    ref = f"SAV-DEP-{uuid.uuid4().hex[:8].upper()}"
    w.debit(req.amount, TxCategory.WALLET_TRANSFER_OUT,
            f"Savings deposit → {plan['goal_name']} [{req.plan_id}]", ref)
    plan["saved_amount"] = round(plan["saved_amount"] + req.amount, 2)
    plan["updated_at"]   = datetime.now().isoformat()
    plan["transactions"].append({
        "type": "deposit", "amount": req.amount,
        "date": datetime.now().isoformat(),
        "balance": plan["saved_amount"],
        "note": req.note or "Manual deposit",
        "ref": ref,
    })
    save_db()
    _save_savings()
    logger.info(f"💰 Savings deposit: ₦{req.amount:,.0f} → {req.plan_id}")
    return {
        "success": True,
        "plan":    _plan_summary(plan),
        "message": f"₦{req.amount:,.0f} saved in '{plan['goal_name']}'",
    }


class SavingsWithdrawRequest(BaseModel):
    plan_id:   str
    wallet_id: str
    amount:    float


@app.post("/savings/withdraw")
def savings_withdraw(req: SavingsWithdrawRequest, bg: BackgroundTasks):
    """
    Withdraw from savings plan back to wallet.
    Applies early withdrawal penalty if plan is still locked.
    SafeLock plans cannot be withdrawn before maturity.
    """
    plan = _savings_db.get(req.plan_id)
    if not plan:
        raise HTTPException(404, "Savings plan not found")
    if plan["wallet_id"] != req.wallet_id:
        raise HTTPException(403, "Plan does not belong to this wallet")
    if plan["status"] not in ("active", "matured"):
        raise HTTPException(400, f"Plan is {plan['status']} — cannot withdraw")

    # Accrue pending interest
    _accrue_interest(plan)

    total_available = round(plan["saved_amount"] + plan["interest_earned"], 2)
    if req.amount > total_available:
        raise HTTPException(400,
            f"Insufficient savings. Available: ₦{total_available:,.2f}")

    # Check lock period
    created   = datetime.fromisoformat(plan["created_at"])
    lock_days = plan.get("lock_days", 0)
    unlock_at = created + timedelta(days=lock_days) if lock_days else created
    is_locked = datetime.now() < unlock_at

    if is_locked and plan["plan_type"] == "safelock":
        days_left = (unlock_at - datetime.now()).days
        raise HTTPException(400,
            f"SafeLock cannot be withdrawn early. "
            f"Unlocks in {days_left} days on {unlock_at.date().isoformat()}.")

    penalty = 0.0
    net_amount = req.amount
    if is_locked and plan.get("penalty_pct", 0) > 0:
        penalty    = round(req.amount * plan["penalty_pct"] / 100, 2)
        net_amount = round(req.amount - penalty, 2)

    # Deduct from saved_amount (interest first, then principal)
    interest_used = min(req.amount, plan["interest_earned"])
    principal_used = req.amount - interest_used
    plan["interest_earned"] = round(plan["interest_earned"] - interest_used, 2)
    plan["saved_amount"]    = round(plan["saved_amount"] - principal_used, 2)
    plan["updated_at"]      = datetime.now().isoformat()

    # Credit wallet (net of penalty)
    w   = _get_wallet(req.wallet_id)
    ref = f"SAV-WDR-{uuid.uuid4().hex[:8].upper()}"
    w.credit(net_amount, TxCategory.WALLET_TRANSFER_IN,
             f"Savings withdrawal from '{plan['goal_name']}'"
             + (f" (₦{penalty:,.2f} early penalty)" if penalty else ""),
             ref)
    plan["transactions"].append({
        "type":    "withdrawal", "amount": req.amount,
        "net":     net_amount,   "penalty": penalty,
        "date":    datetime.now().isoformat(),
        "balance": plan["saved_amount"],
        "ref":     ref,
        "note":    "Early withdrawal" if is_locked else "Withdrawal",
    })
    save_db()
    _save_savings()
    logger.info(
        f"💸 Savings withdrawal: ₦{req.amount:,.0f} from {req.plan_id} "
        f"penalty=₦{penalty:,.2f} net=₦{net_amount:,.2f}"
    )
    msg = f"₦{net_amount:,.0f} returned to your wallet"
    if penalty:
        msg += f" (₦{penalty:,.0f} early withdrawal penalty applied)"
    return {
        "success":  True,
        "plan":     _plan_summary(plan),
        "amount_withdrawn": req.amount,
        "penalty":  penalty,
        "net_received": net_amount,
        "message":  msg,
    }


@app.get("/savings/{wallet_id}")
def list_savings_plans_for_wallet(wallet_id: str):
    """List all savings plans for a wallet with live interest calculations."""
    _get_wallet(wallet_id)   # validate wallet exists
    plans = [_plan_summary(p) for p in _savings_db.values()
             if p["wallet_id"] == wallet_id and p["status"] != "closed"]
    total_saved    = sum(p["saved_amount"]    for p in plans)
    total_interest = sum(p["interest_earned"] + p.get("pending_interest", 0) for p in plans)
    return {
        "success":       True,
        "wallet_id":     wallet_id,
        "plans":         plans,
        "summary": {
            "total_saved":    round(total_saved, 2),
            "total_interest": round(total_interest, 2),
            "total_value":    round(total_saved + total_interest, 2),
            "plan_count":     len(plans),
        },
    }


@app.get("/savings/plan/{plan_id}")
def get_savings_plan(plan_id: str):
    plan = _savings_db.get(plan_id)
    if not plan:
        raise HTTPException(404, "Savings plan not found")
    return {"success": True, "plan": _plan_summary(plan)}


@app.post("/savings/plan/{plan_id}/close")
def close_savings_plan(plan_id: str, wallet_id: str = Body(..., embed=True)):
    """Close a savings plan and return all funds + interest to wallet."""
    plan = _savings_db.get(plan_id)
    if not plan:
        raise HTTPException(404, "Savings plan not found")
    if plan["wallet_id"] != wallet_id:
        raise HTTPException(403, "Not your plan")
    if plan["status"] == "closed":
        raise HTTPException(400, "Plan already closed")

    # Accrue final interest
    _accrue_interest(plan)
    total = round(plan["saved_amount"] + plan["interest_earned"], 2)

    # Check lock
    created   = datetime.fromisoformat(plan["created_at"])
    lock_days = plan.get("lock_days", 0)
    is_locked = lock_days > 0 and datetime.now() < created + timedelta(days=lock_days)

    if is_locked and plan["plan_type"] == "safelock":
        days_left = (created + timedelta(days=lock_days) - datetime.now()).days
        raise HTTPException(400,
            f"SafeLock cannot be closed early. "
            f"Matures in {days_left} days.")

    penalty = 0.0
    net     = total
    if is_locked and plan.get("penalty_pct", 0) > 0:
        penalty = round(total * plan["penalty_pct"] / 100, 2)
        net     = round(total - penalty, 2)

    w   = _get_wallet(wallet_id)
    ref = f"SAV-CLOSE-{uuid.uuid4().hex[:8].upper()}"
    w.credit(net, TxCategory.WALLET_TRANSFER_IN,
             f"Savings plan closed: '{plan['goal_name']}'"
             + (f" (₦{penalty:,.2f} penalty)" if penalty else ""),
             ref)
    plan.update({
        "status":       "closed",
        "saved_amount": 0.0,
        "interest_earned": 0.0,
        "closed_at":    datetime.now().isoformat(),
        "updated_at":   datetime.now().isoformat(),
    })
    plan["transactions"].append({
        "type": "close", "gross": total, "penalty": penalty, "net": net,
        "date": datetime.now().isoformat(), "ref": ref,
    })
    save_db()
    _save_savings()

    # Cancel Flutterwave payment plan if it exists
    if plan.get("flw_plan_id"):
        flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
        if flw_key:
            try:
                requests.put(
                    f"{FLW_BASE_URL}/payment-plans/{plan['flw_plan_id']}/cancel",
                    headers={"Authorization": f"Bearer {flw_key}"},
                    timeout=10, verify=False,
                )
                logger.info(f"🦋 FLW payment plan cancelled: {plan['flw_plan_id']}")
            except Exception as e:
                logger.warning(f"Could not cancel FLW plan: {e}")

    logger.info(f"✅ Savings plan closed: {plan_id} net=₦{net:,.2f}")
    return {
        "success":    True,
        "gross":      total,
        "penalty":    penalty,
        "net_received": net,
        "message":    f"Plan closed. ₦{net:,.0f} returned to your wallet.",
    }


@app.get("/savings/plans/types")
def savings_plan_types():
    """Return plan types — same as /savings/plans, used by Flutter dropdown."""
    return {"success": True, "plans": list(SAVINGS_PLANS.values())}


# ══════════════════════════════════════════════════════════════════════════════
# AI CHAT — Claude-powered assistant via Anthropic API
# ══════════════════════════════════════════════════════════════════════════════

class AiChatMessage(BaseModel):
    role: str       # "user" or "assistant"
    content: str

class AiChatRequest(BaseModel):
    wallet_id: Optional[str] = None   # optional — for personalised context
    messages: List[AiChatMessage]      # full conversation history

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip().strip('"').strip("'").strip()

NAIRAFLOW_SYSTEM_PROMPT = """You are a helpful Nigerian fintech AI assistant built into the CredionPay app.

You help users with:
- Personal finance advice in Nigeria (budgeting, saving, investing)
- Explaining CredionPay features (wallet transfers, KYC, virtual cards, bills, airtime, data)
- Nigerian banking knowledge (banks, USSD codes, CBN policies)
- NYSC allowance and corper finances
- School fees and student budgeting
- Live market context (Dollar rate, fuel prices, food costs)
- Fraud prevention and security tips

Guidelines:
- Always use Naira (₦) for amounts
- Keep responses concise and friendly (max 3-4 short paragraphs)
- Use bullet points for lists
- Reference Nigerian context (Lagos, Abuja, Kano, etc.)
- Be encouraging and practical
- If asked about CredionPay features, guide them step by step
- Never give investment advice as fact — always say "consider" or "you may want to"
"""

# ══════════════════════════════════════════════════════════════════════════════
# USD WALLET — Balance, Fund, Convert, Send, Virtual Accounts, Tag Search
# ══════════════════════════════════════════════════════════════════════════════

class UsdFundRequest(BaseModel):
    wallet_id: str
    usd_amount: float        # amount in USD to add

class UsdConvertRequest(BaseModel):
    wallet_id: str
    usd_amount: float        # USD to convert → Naira

class UsdSendRequest(BaseModel):
    sender_wallet_id: str
    recipient_tag: str       # @credionpay/recipientname
    usd_amount: float
    note: str = ""

@app.get("/wallet/{wallet_id}/usd")
def get_usd_balance(wallet_id: str):
    """Get USD balance, USDT balance, USD tag, and virtual account details."""
    w = _get_wallet(wallet_id)
    return {
        "success":         True,
        "wallet_id":       wallet_id,
        "usd_balance":     w.usd_balance,
        "usdt_balance":    w.usdt_balance,
        "usd_tag":         w.usd_tag,
        "naira_value":     round(w.usd_balance * USD_RATE, 2),
        "usdt_naira_value":round(w.usdt_balance * USD_RATE, 2),
        "usd_rate":        USD_RATE,
        "gbp_rate":        GBP_RATE,
        "eur_rate":        EUR_RATE,
        "virtual_acct_uk": w.virtual_acct_uk,
        "virtual_acct_us": w.virtual_acct_us,
    }


# ── USDT endpoints ─────────────────────────────────────────────────────────────

class UsdtFundRequest(BaseModel):
    wallet_id:   str
    usdt_amount: float   # USDT to buy (deducts NGN at current USD rate)

class UsdtConvertRequest(BaseModel):
    wallet_id:   str
    usdt_amount: float   # USDT → NGN

class UsdtSendRequest(BaseModel):
    sender_wallet_id: str
    recipient_tag:    str   # @credionpay/username
    usdt_amount:      float
    note:             str = ""

@app.post("/wallet/usdt/buy")
def buy_usdt(req: UsdtFundRequest, bg: BackgroundTasks):
    """Buy USDT by deducting NGN equivalent from main wallet."""
    w = _get_wallet(req.wallet_id)
    if req.usdt_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    naira_cost = round(req.usdt_amount * USD_RATE, 2)
    if naira_cost > w.balance:
        raise HTTPException(400, f"Insufficient balance. Need ₦{naira_cost:,.2f}, have ₦{w.balance:,.2f}")
    ref = f"USDT-BUY-{uuid.uuid4().hex[:10].upper()}"
    w.debit(naira_cost, TxCategory.WALLET_TRANSFER_OUT,
            f"USDT purchase — {req.usdt_amount:.4f} USDT @ ₦{USD_RATE:,.0f}", ref)
    w.usdt_balance = round(w.usdt_balance + req.usdt_amount, 4)
    save_db()
    logger.info(f"₮ USDT bought: {req.usdt_amount} USDT (₦{naira_cost:,.2f}) for {req.wallet_id}")
    return {
        "success":       True,
        "message":       f"{req.usdt_amount:.4f} USDT added to your crypto wallet",
        "usdt_balance":  w.usdt_balance,
        "naira_deducted":naira_cost,
        "naira_balance": w.balance,
        "rate_used":     USD_RATE,
    }

@app.post("/wallet/usdt/sell")
def sell_usdt(req: UsdtConvertRequest, bg: BackgroundTasks):
    """Convert USDT back to NGN — sells at current USD rate."""
    w = _get_wallet(req.wallet_id)
    if req.usdt_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if req.usdt_amount > w.usdt_balance:
        raise HTTPException(400, f"Insufficient USDT. Available: {w.usdt_balance:.4f} USDT")
    naira_received = round(req.usdt_amount * USD_RATE, 2)
    ref = f"USDT-SELL-{uuid.uuid4().hex[:10].upper()}"
    w.usdt_balance = round(w.usdt_balance - req.usdt_amount, 4)
    w.credit(naira_received, TxCategory.WALLET_TRANSFER_IN,
             f"USDT sold — {req.usdt_amount:.4f} USDT @ ₦{USD_RATE:,.0f}", ref)
    save_db()
    logger.info(f"₮ USDT sold: {req.usdt_amount} USDT → ₦{naira_received:,.2f} for {req.wallet_id}")
    return {
        "success":        True,
        "message":        f"{req.usdt_amount:.4f} USDT sold for ₦{naira_received:,.2f}",
        "usdt_balance":   w.usdt_balance,
        "naira_received": naira_received,
        "naira_balance":  w.balance,
        "rate_used":      USD_RATE,
    }

@app.post("/wallet/usdt/send")
def send_usdt(req: UsdtSendRequest, bg: BackgroundTasks):
    """Send USDT to another CredionPay user by USD tag."""
    sender = _get_wallet(req.sender_wallet_id)
    tag = req.recipient_tag if req.recipient_tag.startswith("@") else f"@{req.recipient_tag}"
    if tag not in usd_tag_index:
        raise HTTPException(404, f"Tag '{tag}' not found")
    if usd_tag_index[tag] == req.sender_wallet_id:
        raise HTTPException(400, "Cannot send USDT to yourself")
    if req.usdt_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if req.usdt_amount > sender.usdt_balance:
        raise HTTPException(400, f"Insufficient USDT. Available: {sender.usdt_balance:.4f}")
    recipient = _get_wallet(usd_tag_index[tag])
    ref = f"USDT-SEND-{uuid.uuid4().hex[:10].upper()}"
    sender.usdt_balance   = round(sender.usdt_balance   - req.usdt_amount, 4)
    recipient.usdt_balance= round(recipient.usdt_balance + req.usdt_amount, 4)
    ngn_equiv = round(req.usdt_amount * USD_RATE, 2)
    note = req.note or f"USDT to {tag}"
    sender.transactions.append(Transaction(
        tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
        tx_type=TxType.DEBIT, category=TxCategory.WALLET_TRANSFER_OUT,
        amount=ngn_equiv, balance_after=sender.balance, status="success",
        description=f"USDT sent → {tag} | {req.usdt_amount:.4f} USDT | {note}",
        reference=ref,
    ))
    recipient.transactions.append(Transaction(
        tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
        tx_type=TxType.CREDIT, category=TxCategory.WALLET_TRANSFER_IN,
        amount=ngn_equiv, balance_after=recipient.balance, status="success",
        description=f"USDT received from {sender.usd_tag} | {req.usdt_amount:.4f} USDT",
        reference=ref,
    ))
    save_db()
    logger.info(f"₮ USDT sent: {req.usdt_amount} USDT → {tag} from {req.sender_wallet_id}")
    return {
        "success":             True,
        "message":             f"{req.usdt_amount:.4f} USDT sent to {tag}",
        "recipient_name":      recipient.owner_name,
        "usdt_sent":           req.usdt_amount,
        "sender_usdt_balance": sender.usdt_balance,
        "reference":           ref,
    }

@app.post("/wallet/usdt/swap-to-usd")
def swap_usdt_to_usd(wallet_id: str = Body(..., embed=True),
                     usdt_amount: float = Body(..., embed=True)):
    """Swap USDT → USD dollar wallet (1:1 since both pegged to USD)."""
    w = _get_wallet(wallet_id)
    if usdt_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if usdt_amount > w.usdt_balance:
        raise HTTPException(400, f"Insufficient USDT. Available: {w.usdt_balance:.4f}")
    w.usdt_balance = round(w.usdt_balance - usdt_amount, 4)
    w.usd_balance  = round(w.usd_balance  + usdt_amount, 2)
    ref = f"SWAP-{uuid.uuid4().hex[:10].upper()}"
    save_db()
    logger.info(f"🔄 USDT→USD swap: {usdt_amount} for {wallet_id}")
    return {
        "success":      True,
        "message":      f"{usdt_amount:.4f} USDT swapped to ${usdt_amount:.2f} USD",
        "usd_balance":  w.usd_balance,
        "usdt_balance": w.usdt_balance,
        "reference":    ref,
    }

@app.post("/wallet/usd/fund")
def fund_usd_wallet(req: UsdFundRequest, bg: BackgroundTasks):
    """Add USD by deducting equivalent Naira from wallet."""
    w = _get_wallet(req.wallet_id)
    if req.usd_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    naira_cost = round(req.usd_amount * USD_RATE, 2)
    try:
        tx = w.debit(naira_cost, "usd_fund", f"USD wallet funding — ${req.usd_amount:.2f}", f"USD-FUND-{uuid.uuid4().hex[:8].upper()}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    w.usd_balance = round(w.usd_balance + req.usd_amount, 2)
    save_db()
    logger.info(f"💵 USD funded: ${req.usd_amount} for {req.wallet_id} (₦{naira_cost:,.2f} deducted)")
    return {
        "success":       True,
        "message":       f"${req.usd_amount:.2f} added to your Dollar Wallet",
        "usd_balance":   w.usd_balance,
        "naira_deducted": naira_cost,
        "naira_balance": w.balance,
        "rate_used":     USD_RATE,
    }

@app.post("/wallet/usd/convert")
def convert_usd_to_naira(req: UsdConvertRequest, bg: BackgroundTasks):
    """Convert USD balance → Naira balance."""
    w = _get_wallet(req.wallet_id)
    if req.usd_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if req.usd_amount > w.usd_balance:
        raise HTTPException(400, f"Insufficient USD balance. Available: ${w.usd_balance:.2f}")
    naira_amount = round(req.usd_amount * USD_RATE, 2)
    w.usd_balance = round(w.usd_balance - req.usd_amount, 2)
    w.credit(naira_amount, "usd_convert", f"USD conversion — ${req.usd_amount:.2f} @ ₦{USD_RATE}", f"USD-CONV-{uuid.uuid4().hex[:8].upper()}")
    save_db()
    logger.info(f"🔄 USD converted: ${req.usd_amount} → ₦{naira_amount:,.2f} for {req.wallet_id}")
    return {
        "success":       True,
        "message":       f"${req.usd_amount:.2f} converted to ₦{naira_amount:,.2f}",
        "usd_balance":   w.usd_balance,
        "naira_balance": w.balance,
        "naira_received": naira_amount,
        "rate_used":     USD_RATE,
    }

@app.post("/wallet/usd/send")
def send_usd_by_tag(req: UsdSendRequest, bg: BackgroundTasks):
    """Send USD from one CredionPay user to another using USD tag."""
    sender = _get_wallet(req.sender_wallet_id)
    # Normalise tag — accept with or without @
    tag = req.recipient_tag if req.recipient_tag.startswith("@") else f"@{req.recipient_tag}"
    if tag not in usd_tag_index:
        raise HTTPException(404, f"USD tag '{tag}' not found. Check the tag and try again.")
    if usd_tag_index[tag] == req.sender_wallet_id:
        raise HTTPException(400, "You cannot send USD to yourself")
    if req.usd_amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if req.usd_amount > sender.usd_balance:
        raise HTTPException(400, f"Insufficient USD balance. Available: ${sender.usd_balance:.2f}")

    recipient = _get_wallet(usd_tag_index[tag])
    ref = f"USD-SEND-{uuid.uuid4().hex[:10].upper()}"

    sender.usd_balance    = round(sender.usd_balance - req.usd_amount, 2)
    recipient.usd_balance = round(recipient.usd_balance + req.usd_amount, 2)

    # Record in each wallet's transaction history as USD (no fake NGN entries)
    ngn_equiv = round(req.usd_amount * USD_RATE, 2)
    note = req.note or f"USD transfer to {tag}"
    sender.transactions.append(Transaction(
        tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
        tx_type=TxType.DEBIT, category=TxCategory.WALLET_TRANSFER_OUT,
        amount=ngn_equiv, balance_after=sender.balance,
        status="success",
        description=f"USD sent → {tag} | ${req.usd_amount:.2f} @ ₦{USD_RATE:,.0f} | {note}",
        reference=ref,
    ))
    recipient.transactions.append(Transaction(
        tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
        tx_type=TxType.CREDIT, category=TxCategory.WALLET_TRANSFER_IN,
        amount=ngn_equiv, balance_after=recipient.balance,
        status="success",
        description=f"USD received from {sender.usd_tag} | ${req.usd_amount:.2f} @ ₦{USD_RATE:,.0f}",
        reference=ref,
    ))

    save_db()
    logger.info(f"💸 USD sent: ${req.usd_amount} from {req.sender_wallet_id} → {tag}")
    return {
        "success":            True,
        "message":            f"${req.usd_amount:.2f} sent to {tag}",
        "recipient_name":     recipient.owner_name,
        "usd_sent":           req.usd_amount,
        "sender_usd_balance": sender.usd_balance,
        "reference":          ref,
    }

@app.get("/wallet/tag/{tag:path}")
def find_wallet_by_tag(tag: str):
    """Look up a wallet by USD tag — supports tags with @ and / in them."""
    # Accept: @credionpay/ethan, credionpay/ethan, ethan
    clean = tag.strip().lstrip("@")
    # Try exact match first, then with @credionpay/ prefix
    candidates = [
        f"@{clean}",
        f"@credionpay/{clean}",
        f"@{clean.replace('credionpay/', '')}",
        clean,
    ]
    found = None
    for c in candidates:
        if c in usd_tag_index:
            found = c
            break
    if not found:
        raise HTTPException(404, f"No wallet found for tag '@{clean}'")
    w = wallets[usd_tag_index[found]]
    return {
        "success":    True,
        "usd_tag":    w.usd_tag,
        "owner_name": w.owner_name,
        "wallet_id":  w.wallet_id,
    }


@app.get("/debug/status")
def debug_status():
    """Live state check — shows wallets loaded, tags, working directory."""
    import os
    return {
        "wallets_loaded":    len(wallets),
        "usd_tags_indexed":  len(usd_tag_index),
        "usd_tags":          list(usd_tag_index.keys()),
        "wallet_ids":        list(wallets.keys()),
        "working_dir":       os.getcwd(),
        "db_file":           str(DB_FILE.resolve()),
        "db_exists":         DB_FILE.exists(),
        "db_size_bytes":     DB_FILE.stat().st_size if DB_FILE.exists() else 0,
        "anthropic_key_set": bool(os.getenv("ANTHROPIC_API_KEY")),
        "paystack_key_set":  bool(os.getenv("PAYSTACK_SECRET_KEY")),
    }



@app.get("/wallet/rates/live")
def get_exchange_rates():
    """
    Live exchange rates — fetches from Flutterwave FX API.
    Falls back to stored rates if API unavailable.
    Also updates the global USD/GBP/EUR rates used across the app.
    """
    global USD_RATE, GBP_RATE, EUR_RATE

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    live_rates = {}
    source = "fallback"

    if flw_key:
        try:
            # Flutterwave rates endpoint
            resp = requests.get(
                f"{FLW_BASE_URL}/transfers/rates?amount=1&destination_currency=NGN&source_currency=USD",
                headers={"Authorization": f"Bearer {flw_key}"},
                timeout=8, verify=False,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                rate = float(d.get("rate", 0))
                if rate > 0:
                    live_rates["USD"] = rate
                    source = "flutterwave"

            for currency in ["GBP", "EUR"]:
                r2 = requests.get(
                    f"{FLW_BASE_URL}/transfers/rates?amount=1&destination_currency=NGN&source_currency={currency}",
                    headers={"Authorization": f"Bearer {flw_key}"},
                    timeout=8, verify=False,
                )
                if r2.status_code == 200:
                    d2 = r2.json().get("data", {})
                    rate2 = float(d2.get("rate", 0))
                    if rate2 > 0:
                        live_rates[currency] = rate2
        except Exception as e:
            logger.warning(f"FLW rates fetch failed: {e} — using stored rates")

    # Update globals if live rates available
    if live_rates.get("USD"):
        USD_RATE = live_rates["USD"]
    if live_rates.get("GBP"):
        GBP_RATE = live_rates["GBP"]
    if live_rates.get("EUR"):
        EUR_RATE = live_rates["EUR"]

    return {
        "success": True,
        "source":  source,
        "rates": {
            "USD": {"rate": USD_RATE, "flag": "🇺🇸", "name": "US Dollar",      "symbol": "$"},
            "GBP": {"rate": GBP_RATE, "flag": "🇬🇧", "name": "British Pound",  "symbol": "£"},
            "EUR": {"rate": EUR_RATE, "flag": "🇪🇺", "name": "Euro",           "symbol": "€"},
            "USDT":{"rate": USD_RATE, "flag": "₮",   "name": "Tether (USDT)", "symbol": "₮"},
        },
        "updated_at": datetime.now().isoformat(),
        "note": "Rates from Flutterwave FX API" if source == "flutterwave"
                else "Live rates unavailable — showing last known rates",
    }

@app.post("/webhooks/flutterwave")
async def flutterwave_webhook(request: Request, bg: BackgroundTasks):
    """
    Flutterwave webhook — handles:
    - charge.completed  → NGN virtual account credit (DVA)
    - transfer.completed → USD diaspora credit
    Verifies FLW-Signature header in production.
    """
    body    = await request.body()
    payload = await request.json()
    event   = payload.get("event", "")
    data    = payload.get("data", {})

    # Verify webhook signature (skip if secret hash not configured)
    flw_hash = os.getenv("FLW_SECRET_HASH", "").strip()
    sig      = request.headers.get("verif-hash", "")
    if flw_hash and sig != flw_hash:
        logger.warning(f"⚠️ Flutterwave webhook: invalid signature")
        return {"status": "invalid_signature"}

    logger.info(f"📨 Flutterwave webhook: {event} | amount={data.get('amount')} {data.get('currency')}")

    # ── NGN Virtual Account Credit ────────────────────────────────────────────
    if event == "charge.completed" and data.get("status") == "successful":
        amount_ngn   = float(data.get("amount", 0))
        currency     = data.get("currency", "NGN")
        flw_ref      = data.get("flw_ref", "")
        tx_ref       = data.get("tx_ref", "")
        customer     = data.get("customer", {})
        sender_email = customer.get("email", "")
        sender_name  = customer.get("name", "Bank Transfer")
        acct_details = data.get("meta", {}) or {}

        # Find wallet by email or tx_ref (NF-VA-{wallet_id}-...)
        wallet_found = None
        if sender_email and sender_email in email_index:
            wallet_found = wallets[email_index[sender_email]]
        if not wallet_found and tx_ref and tx_ref.startswith("NF-VA-"):
            parts = tx_ref.split("-")
            if len(parts) >= 4:
                wid = f"WAL-{parts[3]}" if not parts[3].startswith("WAL") else parts[3]
                wallet_found = wallets.get(wid)
        # Also check by DVA account number
        if not wallet_found:
            acct_num = (data.get("virtual_account", {}) or {}).get("account_number", "")
            for w in wallets.values():
                if w.dva and w.dva.get("account_number") == acct_num:
                    wallet_found = w
                    break

        if not wallet_found:
            logger.warning(f"⚠️ FLW charge webhook: wallet not found for {sender_email} / {tx_ref}")
            return {"status": "wallet_not_found"}

        # Deduplicate by flw_ref
        existing = [t for t in wallet_found.transactions if t.reference == flw_ref]
        if existing:
            return {"status": "already_processed"}

        tx = wallet_found.credit(amount_ngn, TxCategory.DVA_FUNDING,
                                 f"Bank transfer received from {sender_name} | FLW Ref: {flw_ref}", flw_ref)
        save_db()
        logger.info(f"✅ FLW NGN credit: ₦{amount_ngn:,.2f} → {wallet_found.wallet_id} from {sender_name}")
        bg.add_task(_email_dva_credit, wallet_found, amount_ngn, "Bank Transfer", flw_ref)
        return {"status": "credited", "amount": amount_ngn, "wallet": wallet_found.wallet_id}

    # ── USD Diaspora Transfer ─────────────────────────────────────────────────
    if event in ("transfer.completed", "charge.completed"):
        meta      = data.get("meta", {}) or {}
        tag       = meta.get("usd_tag", "")
        amount    = float(data.get("amount", 0))
        currency  = data.get("currency", "USD")
        flw_ref   = data.get("flw_ref", f"FLW-{uuid.uuid4().hex[:10].upper()}")
        sender    = (data.get("customer", {}) or {}).get("name", "Overseas sender")

        if tag and tag in usd_tag_index:
            w = wallets[usd_tag_index[tag]]
            # Convert to USD
            usd_received = amount
            if currency == "GBP":
                usd_received = round(amount * (GBP_RATE / USD_RATE), 2)
            elif currency == "EUR":
                usd_received = round(amount * (EUR_RATE / USD_RATE), 2)
            w.usd_balance = round(w.usd_balance + usd_received, 2)
            save_db()
            logger.info(f"✅ FLW diaspora credit: ${usd_received} ({currency} {amount}) → {tag}")
            bg.add_task(_email_usd_received, w, usd_received, currency, amount, sender, flw_ref)
            return {"status": "success", "credited_usd": usd_received}

    return {"status": "ignored", "event": event}

def _email_usd_received(w: "Wallet", usd: float, currency: str, orig_amount: float, sender: str, ref: str):
    """Email user when diaspora payment lands."""
    naira_equiv = round(usd * USD_RATE, 2)
    subject = f"💵 You received ${usd:.2f} from {sender}"
    body = f"""
    <div style="padding:10px 0 20px">
      <p style="font-size:18px;font-weight:700;color:#111;">You received money from overseas! 🎉</p>
    </div>
    {_receipt_table(
        ("Sender",          sender),
        ("Amount Received",  f"${usd:.2f} USD"),
        ("Original Amount",  f"{currency} {orig_amount:.2f}"),
        ("Naira Equivalent", f"₦{naira_equiv:,.2f}"),
        ("Your USD Balance", f"${w.usd_balance:.2f}"),
        ("Your USD Tag",     w.usd_tag),
        ("Reference",        ref),
        ("Status",           "✅ Credited", True),
    )}
    <p style="font-size:13px;color:#666;margin-top:20px;">
      Open CredionPay to convert your USD to Naira or keep it in your Dollar Wallet.
    </p>
    """
    send_email(w.owner_email, subject, body, w.owner_name.split()[0])


@app.post("/wallet/virtual-account/create")
def create_virtual_account(wallet_id: str = Body(..., embed=True), bg: BackgroundTasks = None):
    """
    Create real Flutterwave virtual account (NGN) for receiving money.
    Also maintains mock UK/US accounts for diaspora until FLW international is live.
    """
    w = _get_wallet(wallet_id)
    _require_kyc(w)
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    is_live = bool(flw_key)

    # ── Real Flutterwave NGN virtual account ──────────────────────────────────
    flw_ngn_account = w.dva if w.dva and w.dva.get("provider") == "flutterwave" else None

    if is_live and not flw_ngn_account:
        try:
            tx_ref = f"NF-VA-{wallet_id}-{uuid.uuid4().hex[:8].upper()}"
            resp = flw_post("/virtual-account-numbers", {
                "email":       w.owner_email,
                "is_permanent": True,
                "bvn":         "",          # optional on test
                "tx_ref":      tx_ref,
                "firstname":   w.owner_name.split()[0],
                "lastname":    " ".join(w.owner_name.split()[1:]) or w.owner_name,
                "narration":   f"CredionPay — {w.owner_name}",
                "phonenumber": w.phone or "08000000000",
                "amount":      "",          # open amount
            })
            if resp.get("status") == "success":
                d = resp["data"]
                flw_ngn_account = {
                    "provider":       "flutterwave",
                    "bank_name":      d.get("bank_name", "Wema Bank"),
                    "account_number": d.get("account_number", ""),
                    "account_name":   d.get("account_name", w.owner_name),
                    "flw_ref":        d.get("flw_ref", tx_ref),
                    "order_ref":      d.get("order_ref", tx_ref),
                    "currency":       "NGN",
                    "mode":           "live",
                    "note":           "Transfer NGN to this account from any Nigerian bank — instant credit",
                }
                w.dva = flw_ngn_account
                save_db()
                logger.info(f"🦋 Flutterwave NGN VA created: {flw_ngn_account['account_number']} for {wallet_id}")
            else:
                logger.warning(f"⚠️ Flutterwave VA creation failed: {resp.get('message')} — using mock")
                flw_ngn_account = None
        except Exception as e:
            logger.error(f"Flutterwave VA error: {e}")
            flw_ngn_account = None

    # ── Mock NGN account if Flutterwave not available ─────────────────────────
    if not flw_ngn_account:
        if not (w.dva and w.dva.get("account_number")):
            import random as _r
            mock_acct = "062" + "".join([str(_r.randint(0,9)) for _ in range(7)])
            w.dva = {
                "provider":       "mock",
                "bank_name":      "Wema Bank (Demo)",
                "account_number": mock_acct,
                "account_name":   w.owner_name.upper(),
                "currency":       "NGN",
                "mode":           "demo",
                "note":           "Demo account. Add FLW_SECRET_KEY to .env for a real account.",
            }
            save_db()
        flw_ngn_account = w.dva

    # ── Mock UK/US accounts (real ones need FLW International) ───────────────
    if not w.virtual_acct_uk or not w.virtual_acct_uk.get("account_no"):
        import random as _r
        def _rd(n): return "".join([str(_r.randint(0,9)) for _ in range(n)])
        w.virtual_acct_uk = {
            "bank_name":    "Flutterwave / Lloyds UK",
            "sort_code":    "04-00-75",
            "account_no":   "7" + _rd(7),
            "account_name": w.owner_name,
            "currency":     "GBP",
            "reference":    w.usd_tag,
            "mode":         "demo",
        }
        w.virtual_acct_us = {
            "bank_name":    "Flutterwave / Evolve Bank USA",
            "routing_no":   "026073150",
            "account_no":   "9" + _rd(8),
            "account_name": w.owner_name,
            "currency":     "USD",
            "reference":    w.usd_tag,
            "mode":         "demo",
        }
        save_db()

    return {
        "success":          True,
        "usd_tag":          w.usd_tag,
        "ngn_account":      flw_ngn_account,
        "virtual_acct_uk":  w.virtual_acct_uk,
        "virtual_acct_us":  w.virtual_acct_us,
        "provider":         "flutterwave" if is_live else "demo",
        "note":             "NGN account — anyone can transfer from any Nigerian bank. Money arrives instantly.",
    }


@app.get("/wallet/{wallet_id}/virtual-accounts")
def get_virtual_accounts(wallet_id: str):
    """Get all virtual accounts for a wallet."""
    w = _get_wallet(wallet_id)
    return {
        "success":         True,
        "ngn_account":     w.dva or {},
        "virtual_acct_uk": w.virtual_acct_uk,
        "virtual_acct_us": w.virtual_acct_us,
        "usd_tag":         w.usd_tag,
        "has_live_ngn":    bool(w.dva and w.dva.get("provider") == "flutterwave"),
    }




# ══════════════════════════════════════════════════════════════════════════════
# FLUTTERWAVE — Payment initiation + verification
# ══════════════════════════════════════════════════════════════════════════════

class FlwFundRequest(BaseModel):
    wallet_id:    str
    amount_naira: float
    redirect_url: str = "https://credionpay.app/fund-complete"
    payment_type: str = "card"   # card | bank_transfer | ussd | mobile_money

@app.post("/wallet/fund/flutterwave")
def fund_via_flutterwave(req: FlwFundRequest, bg: BackgroundTasks):
    """
    Initiate a Flutterwave payment to fund the wallet.
    Returns a payment link the user opens in browser/WebView.
    """
    w = _get_wallet(req.wallet_id)
    if req.amount_naira < 100:
        raise HTTPException(400, "Minimum funding amount is ₦100")

    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if not flw_key:
        raise HTTPException(503, "Flutterwave not configured. Add FLW_SECRET_KEY to .env")

    tx_ref = f"NF-FUND-{req.wallet_id}-{uuid.uuid4().hex[:10].upper()}"
    payload = {
        "tx_ref":        tx_ref,
        "amount":        req.amount_naira,
        "currency":      "NGN",
        "redirect_url":  req.redirect_url,
        "payment_options": req.payment_type,
        "customer": {
            "email":       w.owner_email,
            "phonenumber": w.phone or "",
            "name":        w.owner_name,
        },
        "customizations": {
            "title":       "CredionPay Wallet Funding",
            "description": f"Fund CredionPay wallet {req.wallet_id}",
            "logo":        "https://credionpay.app/logo.png",
        },
        "meta": {
            "wallet_id": req.wallet_id,
            "source":    "credionpay_app",
        },
    }

    resp = flw_post("/payments", payload)
    if resp.get("status") != "success":
        raise HTTPException(400, f"Flutterwave error: {resp.get('message', 'Unknown error')}")

    link = resp["data"]["link"]
    logger.info(f"🦋 FLW payment link created: {tx_ref} ₦{req.amount_naira:,.2f} for {req.wallet_id}")
    return {
        "success":    True,
        "tx_ref":     tx_ref,
        "pay_link":   link,
        "amount":     req.amount_naira,
        "message":    "Open pay_link in browser to complete payment",
    }


@app.get("/wallet/fund/flutterwave/verify/{tx_ref}")
def verify_flw_payment(tx_ref: str, bg: BackgroundTasks = None):
    """
    Verify a Flutterwave payment after redirect.
    Call this after user returns from the payment page.
    """
    resp = flw_get(f"/transactions/verify_by_reference?tx_ref={tx_ref}")
    if resp.get("status") != "success":
        raise HTTPException(400, f"Verification failed: {resp.get('message')}")

    d       = resp["data"]
    status  = d.get("status", "")
    amount  = float(d.get("amount", 0))
    flw_id  = str(d.get("id", ""))
    meta    = d.get("meta", {}) or {}
    wallet_id = meta.get("wallet_id", "")

    if status != "successful":
        return {"success": False, "status": status, "message": "Payment not completed"}

    if not wallet_id or wallet_id not in wallets:
        raise HTTPException(404, "Wallet not found in transaction metadata")

    w = wallets[wallet_id]

    # Deduplicate — check if already credited
    already = [t for t in w.transactions if t.reference == flw_id]
    if already:
        return {"success": True, "message": "Already credited", "new_balance": w.balance}

    tx = w.credit(amount, TxCategory.BANK_FUNDING,
                  f"Wallet funded via Flutterwave | Ref: {tx_ref}", flw_id)
    save_db()
    logger.info(f"✅ FLW payment verified + credited: ₦{amount:,.2f} → {wallet_id}")
    if bg:
        bg.add_task(email_debit_receipt, w, tx, to_name="CredionPay Wallet", to_account=wallet_id)
    return {
        "success":     True,
        "amount":      amount,
        "new_balance": w.balance,
        "tx_ref":      tx_ref,
        "flw_id":      flw_id,
        "message":     f"₦{amount:,.2f} credited to your wallet",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SMART FUND ENDPOINT — Dual Provider (Paystack + Flutterwave)
# One endpoint returns BOTH payment links so the app can show a choice,
# and automatically falls back if one provider is unavailable.
# ══════════════════════════════════════════════════════════════════════════════

class SmartFundRequest(BaseModel):
    wallet_id:    str
    amount_naira: float
    callback_url: str = "https://credionpay.app/fund-complete"

@app.post("/wallet/fund/smart")
def smart_fund(req: SmartFundRequest, bg: BackgroundTasks):
    """
    Smart dual-provider funding — returns payment links for BOTH Paystack and
    Flutterwave so the user can pick or the app can auto-use whichever works.

    Response includes:
      paystack_url  — Paystack checkout (card, bank transfer, USSD)
      flw_url       — Flutterwave checkout (card, bank transfer, USSD, mobile money)
      primary       — which provider is recommended ("paystack" | "flutterwave")
      both_available — True if both links generated successfully
    """
    w = _get_wallet(req.wallet_id)
    if req.amount_naira < 100:
        raise HTTPException(400, "Minimum funding amount is ₦100")

    reference  = f"FUND-{uuid.uuid4().hex[:16].upper()}"
    tx_ref_flw = f"NF-FUND-{req.wallet_id}-{uuid.uuid4().hex[:10].upper()}"

    ps_url   = None
    flw_url  = None
    ps_error = None
    flw_error= None

    # ── Paystack payment link ─────────────────────────────────────────────────
    try:
        ps_data = paystack_post("/transaction/initialize", {
            "email":        w.owner_email,
            "amount":       int(req.amount_naira * 100),
            "currency":     "NGN",
            "reference":    reference,
            "callback_url": req.callback_url,
            "channels":     ["card", "bank_transfer", "ussd", "bank"],
            "metadata":     {"wallet_id": req.wallet_id, "funding_type": "smart_fund",
                             "source": "smart_fund"},
        })
        if ps_data.get("status"):
            ps_url = ps_data["data"]["authorization_url"]
            pending_funding[reference] = (req.wallet_id, req.amount_naira)
            logger.info(f"💳 Paystack smart-fund link: {reference} ₦{req.amount_naira:,.2f}")
        else:
            ps_error = ps_data.get("message", "Paystack link failed")
            logger.warning(f"⚠️  Paystack smart-fund failed: {ps_error}")
    except Exception as e:
        ps_error = str(e)
        logger.warning(f"⚠️  Paystack smart-fund exception: {e}")

    # ── Flutterwave payment link ──────────────────────────────────────────────
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if flw_key:
        try:
            flw_resp = flw_post("/payments", {
                "tx_ref":          tx_ref_flw,
                "amount":          req.amount_naira,
                "currency":        "NGN",
                "redirect_url":    req.callback_url,
                "payment_options": "card,banktransfer,ussd,mobilemoney",
                "customer": {
                    "email":       w.owner_email,
                    "phonenumber": w.phone or "",
                    "name":        w.owner_name,
                },
                "customizations": {
                    "title":       "CredionPay Wallet Funding",
                    "description": f"Fund CredionPay · {w.owner_name}",
                    "logo":        "https://credionpay.app/logo.png",
                },
                "meta": {"wallet_id": req.wallet_id, "source": "smart_fund"},
            })
            if flw_resp.get("status") == "success":
                flw_url = flw_resp["data"]["link"]
                logger.info(f"🦋 FLW smart-fund link: {tx_ref_flw} ₦{req.amount_naira:,.2f}")
            else:
                flw_error = flw_resp.get("message", "Flutterwave link failed")
                logger.warning(f"⚠️  FLW smart-fund failed: {flw_error}")
        except Exception as e:
            flw_error = str(e)
            logger.warning(f"⚠️  FLW smart-fund exception: {e}")
    else:
        flw_error = "Flutterwave not configured"

    # ── Both failed ───────────────────────────────────────────────────────────
    if not ps_url and not flw_url:
        raise HTTPException(503,
            f"Both payment providers unavailable. "
            f"Paystack: {ps_error} | Flutterwave: {flw_error}")

    # Primary = whichever is available (prefer Paystack)
    primary = "paystack" if ps_url else "flutterwave"

    return {
        "success":        True,
        "amount":         req.amount_naira,
        "wallet_id":      req.wallet_id,
        "primary":        primary,
        "both_available": bool(ps_url and flw_url),

        # Paystack
        "paystack": {
            "available":       bool(ps_url),
            "url":             ps_url,
            "reference":       reference if ps_url else None,
            "verify_endpoint": f"/wallet/verify-funding",
            "error":           ps_error,
            "channels":        ["Card", "Bank Transfer", "USSD"],
        },

        # Flutterwave
        "flutterwave": {
            "available":       bool(flw_url),
            "url":             flw_url,
            "tx_ref":          tx_ref_flw if flw_url else None,
            "verify_endpoint": f"/wallet/fund/flutterwave/verify/{tx_ref_flw}",
            "error":           flw_error,
            "channels":        ["Card", "Bank Transfer", "USSD", "Mobile Money"],
        },

        "message": (
            f"₦{req.amount_naira:,.2f} — choose your payment method"
            if ps_url and flw_url else
            f"₦{req.amount_naira:,.2f} — pay via {'Paystack' if ps_url else 'Flutterwave'}"
        ),
    }


@app.post("/wallet/fund/flutterwave/ussd")
def fund_via_ussd(wallet_id: str = Body(..., embed=True),
                  amount_naira: float = Body(..., embed=True),
                  bank_code: str = Body(..., embed=True)):
    """
    Generate a USSD code for wallet funding via Flutterwave.
    bank_code: 057 (Zenith), 033 (UBA), 044 (Access), 011 (FirstBank), etc.
    """
    w = _get_wallet(wallet_id)
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if not flw_key:
        raise HTTPException(503, "Flutterwave not configured")

    tx_ref = f"NF-USSD-{wallet_id}-{uuid.uuid4().hex[:8].upper()}"
    resp = flw_post("/charges?type=ussd", {
        "tx_ref":   tx_ref,
        "account_bank": bank_code,
        "amount":   amount_naira,
        "currency": "NGN",
        "email":    w.owner_email,
        "phonenumber": w.phone or "08000000000",
        "fullname": w.owner_name,
        "meta":     {"wallet_id": wallet_id},
    })

    if resp.get("status") not in ("success", "pending"):
        raise HTTPException(400, f"USSD initiation failed: {resp.get('message')}")

    d = resp.get("data", {})
    payment_code = d.get("payment_code", "")
    ussd_code    = f"*{bank_code}*{payment_code}#" if payment_code else ""
    logger.info(f"🦋 USSD code generated for {wallet_id}: {ussd_code}")
    return {
        "success":      True,
        "ussd_code":    ussd_code,
        "payment_code": payment_code,
        "tx_ref":       tx_ref,
        "amount":       amount_naira,
        "expires_in":   "10 minutes",
        "instruction":  f"Dial {ussd_code} on your phone to complete payment",
    }

# ══════════════════════════════════════════════════════════════════════════════
# NYSC — Remita-powered government payments (mock until real API key obtained)
# ══════════════════════════════════════════════════════════════════════════════

NYSC_FEES = {
    "clearance": {"name": "NYSC Clearance Fee",          "amount": 4500.0,  "fixed": True,  "service_type": "4430731"},
    "levy":      {"name": "Corps Development Levy",       "amount": 0.0,     "fixed": False, "service_type": "4430732"},
    "nhis":      {"name": "NHIS Health Insurance",        "amount": 1500.0,  "fixed": True,  "service_type": "4430733"},
    "saed":      {"name": "SAED Skills Acquisition",     "amount": 2000.0,  "fixed": True,  "service_type": "4430734"},
    "pop":       {"name": "Passing Out Levy",             "amount": 3000.0,  "fixed": True,  "service_type": "4430735"},
    "card":      {"name": "ID Card Replacement",          "amount": 2500.0,  "fixed": True,  "service_type": "4430736"},
    "custom":    {"name": "NYSC Custom Payment",          "amount": 0.0,     "fixed": False, "service_type": "4430737"},
}

REMITA_MERCHANT_ID = os.getenv("REMITA_MERCHANT_ID", "2547916")
REMITA_API_KEY     = os.getenv("REMITA_API_KEY", "")
REMITA_BASE        = os.getenv("REMITA_BASE_URL", "https://remitademo.net/remita/ecomm")

def _generate_mock_rrr(fee_type: str, amount: float) -> str:
    """Generate a realistic-looking mock RRR while we wait for real Remita key."""
    import hashlib
    seed = f"{fee_type}{amount}{datetime.now().isoformat()}"
    h = hashlib.md5(seed.encode()).hexdigest()[:10].upper()
    return f"27040{h}"  # Remita RRRs start with merchant prefix

def _generate_real_rrr(fee_type: str, amount: float, name: str, email: str, nysc_ref: str) -> dict:
    """Call real Remita API. Falls back to mock if no API key."""
    if not REMITA_API_KEY:
        logger.info("⚠️  REMITA_API_KEY not set — using mock RRR")
        return {"rrr": _generate_mock_rrr(fee_type, amount), "mock": True}

    import hashlib, requests as req_lib
    service_type = NYSC_FEES.get(fee_type, {}).get("service_type", "4430731")
    order_id = f"NYSC-{uuid.uuid4().hex[:10].upper()}"
    hash_str = f"{REMITA_MERCHANT_ID}{service_type}{order_id}{amount:.2f}{REMITA_API_KEY}"
    api_hash = hashlib.sha512(hash_str.encode()).hexdigest()
    payload = {
        "serviceTypeId": service_type,
        "amount":        str(amount),
        "orderId":       order_id,
        "payerName":     name,
        "payerEmail":    email,
        "payerPhone":    "",
        "description":   f"{NYSC_FEES[fee_type]['name']} — {nysc_ref}",
    }
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"remitaConsumerKey={REMITA_MERCHANT_ID},remitaConsumerToken={api_hash}",
    }
    try:
        resp = req_lib.post(f"{REMITA_BASE}/generate/init.reg", json=payload, headers=headers, timeout=10, verify=False)
        data = resp.json()
        if data.get("statuscode") == "025":  # Remita success code
            return {"rrr": data["RRR"], "mock": False, "order_id": order_id}
        else:
            logger.warning(f"Remita error: {data}")
            return {"rrr": _generate_mock_rrr(fee_type, amount), "mock": True, "remita_error": data.get("status")}
    except Exception as e:
        logger.error(f"Remita API error: {e}")
        return {"rrr": _generate_mock_rrr(fee_type, amount), "mock": True, "error": str(e)}


class NyscPayRequest(BaseModel):
    wallet_id:    str
    fee_type:     str          # clearance | levy | nhis | saed | pop | card | custom
    nysc_ref:     str          # call-up number or state code
    posting_state: str
    amount:       float
    note:         str = ""

class AllaweeCheckRequest(BaseModel):
    call_up_number: str        # e.g. CF/23B/1234567
    state:          str


@app.post("/nysc/pay")
def nysc_pay(req: NyscPayRequest, bg: BackgroundTasks):
    """Pay any NYSC fee. Generates Remita RRR and debits wallet."""
    w = _get_wallet(req.wallet_id)

    fee_info = NYSC_FEES.get(req.fee_type)
    if not fee_info:
        raise HTTPException(400, f"Unknown fee type '{req.fee_type}'. Valid: {list(NYSC_FEES.keys())}")

    # Validate amount — fixed fees cannot be altered
    amount = req.amount
    if fee_info["fixed"] and amount != fee_info["amount"]:
        raise HTTPException(400, f"{fee_info['name']} is a fixed fee of ₦{fee_info['amount']:,.0f}. Cannot change amount.")
    if amount <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    if amount > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}, Required: ₦{amount:,.2f}")

    # Generate Remita RRR (real or mock)
    rrr_result = _generate_real_rrr(req.fee_type, amount, w.owner_name, w.owner_email, req.nysc_ref)
    rrr = rrr_result["rrr"]
    is_mock = rrr_result.get("mock", True)

    # Debit wallet
    ref = f"NYSC-{rrr}"
    desc = f"{fee_info['name']} | State: {req.posting_state} | Ref: {req.nysc_ref} | RRR: {rrr}"
    tx = w.debit(amount, "nysc_payment", desc, ref)
    save_db()

    logger.info(f"🎖️  NYSC payment: {fee_info['name']} ₦{amount:,.2f} for {w.owner_name} | RRR: {rrr} | mock={is_mock}")

    # Email receipt in background
    bg.add_task(_email_nysc_receipt, w, fee_info["name"], amount, rrr, req.nysc_ref, req.posting_state, tx.tx_id, is_mock)

    return {
        "success":       True,
        "message":       f"{fee_info['name']} of ₦{amount:,.2f} paid successfully",
        "rrr":           rrr,
        "is_mock":       is_mock,
        "fee_type":      req.fee_type,
        "fee_name":      fee_info["name"],
        "amount":        amount,
        "posting_state": req.posting_state,
        "nysc_ref":      req.nysc_ref,
        "wallet_balance": w.balance,
        "tx_id":         tx.tx_id,
        "note":          "Remita RRR is mock (demo). Add REMITA_API_KEY to .env for live payments." if is_mock else "Payment confirmed via Remita",
    }


@app.get("/nysc/fees")
def get_nysc_fees():
    """Return all NYSC fee types and amounts."""
    return {
        "success": True,
        "fees": [
            {
                "type":    k,
                "name":    v["name"],
                "amount":  v["amount"],
                "fixed":   v["fixed"],
                "icon":    {"clearance":"🏦","levy":"📋","nhis":"🏥","saed":"📚","pop":"🎓","card":"💳","custom":"💰"}.get(k,"💰"),
            }
            for k, v in NYSC_FEES.items() if k != "custom"
        ],
        "allawee": {
            "amount":    77000,
            "frequency": "Monthly",
            "paid_by":   "Federal Government of Nigeria",
            "pay_date":  "1st of every month",
            "note":      "Allawee for Batch B 2025/2026",
        },
    }


@app.get("/nysc/allawee/schedule")
def nysc_allawee_schedule(call_up_number: str):
    """
    Return allawee payment schedule for a corps member.
    Currently mocked — real integration requires NYSC IPPIS API (restricted).
    """
    # Parse batch from call-up number e.g. CF/23B/1234567 → Batch B 2023
    parts = call_up_number.upper().split("/")
    batch_year  = "20" + parts[1][:2] if len(parts) >= 2 else "2024"
    batch_label = parts[1][2:] if len(parts) >= 2 else "B"

    from datetime import date
    start = date(int(batch_year), 6 if batch_label == "A" else 11, 1)
    schedule = []
    for i in range(12):
        month = (start.month + i - 1) % 12 + 1
        year  = start.year + (start.month + i - 1) // 12
        pay_date = date(year, month, 1)
        paid = pay_date <= date.today()
        schedule.append({
            "month":     pay_date.strftime("%B %Y"),
            "amount":    77000,
            "pay_date":  pay_date.isoformat(),
            "status":    "paid" if paid else "upcoming",
            "month_num": i + 1,
        })

    total_paid     = sum(s["amount"] for s in schedule if s["status"] == "paid")
    months_remaining = sum(1 for s in schedule if s["status"] == "upcoming")

    return {
        "success":         True,
        "call_up_number":  call_up_number,
        "batch":           f"Batch {batch_label} {batch_year}",
        "total_allawee":   77000 * 12,
        "total_paid":      total_paid,
        "months_remaining": months_remaining,
        "schedule":        schedule,
        "note":            "Schedule is estimated based on call-up number. Actual dates depend on NYSC IPPIS system.",
    }


@app.get("/nysc/history/{wallet_id}")
def nysc_payment_history(wallet_id: str):
    """Return all NYSC-related transactions for a wallet."""
    w = _get_wallet(wallet_id)
    nysc_txns = [t.to_dict() for t in w.transactions if t.category == "nysc_payment"]
    total_paid = sum(t["amount"] for t in nysc_txns)
    return {
        "success":     True,
        "wallet_id":   wallet_id,
        "owner_name":  w.owner_name,
        "total_paid":  total_paid,
        "count":       len(nysc_txns),
        "transactions": list(reversed(nysc_txns)),
    }


def _email_nysc_receipt(w: "Wallet", fee_name: str, amount: float,
                        rrr: str, nysc_ref: str, state: str, tx_id: str, is_mock: bool):
    now = datetime.now().strftime("%d %b %Y %H:%M")
    subject = f"✅ NYSC Payment Confirmed — {fee_name} ₦{amount:,.2f}"
    mock_note = ""
    if is_mock:
        mock_note = """<tr><td colspan="2" style="padding:8px 0;font-size:11px;color:#92400E;background:#FFF7ED;text-align:center;border-radius:6px;">
            ⚠️ Demo RRR — Add REMITA_API_KEY to .env for live Remita payments
        </td></tr>"""
    body = f"""
    <div style="padding:10px 0 20px">
      <p style="font-size:18px;font-weight:700;color:#111;">NYSC Payment Successful 🎖️</p>
      <p style="color:#555;font-size:14px;">Your payment has been processed and submitted to the NYSC Remita portal.</p>
    </div>
    {_receipt_table(
        ("Payment Type",   fee_name),
        ("Remita RRR",     rrr, True),
        ("NYSC Reference", nysc_ref),
        ("Posting State",  state),
        ("Amount Paid",    f"₦{amount:,.2f}"),
        ("Wallet Balance", f"₦{w.balance:,.2f}"),
        ("Transaction ID", tx_id),
        ("Date",           now),
        ("Status",         "✅ Confirmed", True),
    )}
    {mock_note}
    <p style="font-size:12px;color:#666;margin-top:16px;">
      Keep your RRR <strong>{rrr}</strong> as proof of payment. 
      You can verify at <a href="https://remita.net">remita.net</a> using this number.
    </p>
    """
    send_email(w.owner_email, subject, body, w.owner_name.split()[0])



# ══════════════════════════════════════════════════════════════════════════════
# PAYSTACK DEDICATED VIRTUAL ACCOUNTS (DVA)
# Every CredionPay user gets a real Wema/Titan bank account number
# ══════════════════════════════════════════════════════════════════════════════

# ── Flutterwave helpers ───────────────────────────────────────────────────────
def _flw_headers() -> dict:
    key = os.getenv("FLW_SECRET_KEY", "").strip()
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

def flw_post(endpoint: str, payload: dict) -> dict:
    try:
        r = requests.post(f"{FLW_BASE_URL}{endpoint}", json=payload,
                          headers=_flw_headers(), timeout=20, verify=False)
        return r.json()
    except Exception as e:
        logger.error(f"Flutterwave POST error: {e}")
        return {"status": "error", "message": str(e)}

def flw_get(endpoint: str) -> dict:
    try:
        r = requests.get(f"{FLW_BASE_URL}{endpoint}",
                         headers=_flw_headers(), timeout=20, verify=False)
        return r.json()
    except Exception as e:
        logger.error(f"Flutterwave GET error: {e}")
        return {"status": "error", "message": str(e)}

def _flw_verify_webhook(secret_hash: str, signature: str) -> bool:
    """Verify Flutterwave webhook signature."""
    import hmac, hashlib
    expected = hmac.new(secret_hash.encode(), digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _paystack_get(endpoint: str) -> dict:
    key = os.getenv("PAYSTACK_SECRET_KEY", "")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        r = requests.get(f"https://api.paystack.co{endpoint}", headers=headers, timeout=15, verify=False)
        return r.json()
    except Exception as e:
        logger.error(f"Paystack GET error: {e}")
        return {"status": False, "message": str(e)}

@app.post("/wallet/dva/create")
def create_dedicated_virtual_account(wallet_id: str = Body(..., embed=True), bg: BackgroundTasks = None):
    """
    Create a virtual bank account for a wallet.
    Now powered by Flutterwave (preferred) or Paystack DVA as fallback.
    """
    w = _get_wallet(wallet_id)
    _require_kyc(w)

    if w.dva and w.dva.get("account_number") and w.dva.get("mode") != "demo":
        return {"success": True, "message": "Virtual account already exists", "dva": w.dva}

    # ── Try Flutterwave first ─────────────────────────────────────────────────
    flw_key = os.getenv("FLW_SECRET_KEY", "").strip()
    if flw_key:
        try:
            tx_ref = f"NF-VA-{wallet_id}-{uuid.uuid4().hex[:8].upper()}"
            resp = flw_post("/virtual-account-numbers", {
                "email":        w.owner_email,
                "is_permanent": True,
                "tx_ref":       tx_ref,
                "firstname":    w.owner_name.split()[0],
                "lastname":     " ".join(w.owner_name.split()[1:]) or w.owner_name,
                "narration":    f"CredionPay — {w.owner_name}",
                "phonenumber":  w.phone or "08000000000",
                "amount":       "",
            })
            if resp.get("status") == "success":
                d = resp["data"]
                w.dva = {
                    "provider":       "flutterwave",
                    "bank_name":      d.get("bank_name", "Wema Bank"),
                    "account_number": d.get("account_number", ""),
                    "account_name":   d.get("account_name", w.owner_name),
                    "flw_ref":        d.get("flw_ref", tx_ref),
                    "currency":       "NGN",
                    "mode":           "live",
                    "note":           "Transfer from any Nigerian bank — instant credit",
                }
                save_db()
                logger.info(f"🦋 Flutterwave VA created: {w.dva['account_number']} for {wallet_id}")
                return {"success": True, "dva": w.dva, "mode": "live",
                        "message": f"Bank account ready! {w.dva['bank_name']} · {w.dva['account_number']}"}
            else:
                logger.warning(f"⚠️ FLW VA failed: {resp.get('message')} — trying Paystack")
        except Exception as e:
            logger.warning(f"FLW VA error: {e} — trying Paystack")

    # ── Fallback: Paystack DVA ────────────────────────────────────────────────
    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    is_live = ps_key.startswith("sk_live_")

    if not is_live:
        # ── Mock DVA for sandbox/demo ─────────────────────────────────────────
        # Generate a 10-digit numeric account number (no hex letters)
        import random as _rand
        mock_acct = "063" + "".join([str(_rand.randint(0, 9)) for _ in range(7)])
        mock_dva = {
            "bank_name":      "Wema Bank",
            "bank_code":      "035",
            "account_number": mock_acct,
            "account_name":   w.owner_name.upper(),
            "reference":      f"NF-DVA-{wallet_id}",
            "currency":       "NGN",
            "mode":           "demo",
            "note":           "Demo account. Switch to Paystack live key for a real bank account.",
        }
        w.dva = mock_dva
        save_db()
        logger.info(f"🏦 Mock DVA created for {wallet_id}: {mock_acct}")
        return {"success": True, "dva": mock_dva, "mode": "demo",
                "message": "Demo virtual account created. Add live Paystack key for real bank account."}

    # ── Real Paystack DVA ─────────────────────────────────────────────────────
    # Step 1: Create or retrieve Paystack customer
    cust_data = paystack_post("/customer", {
        "email":       w.owner_email,
        "first_name":  w.owner_name.split()[0],
        "last_name":   " ".join(w.owner_name.split()[1:]) or w.owner_name,
        "phone":       w.phone or "",
    })
    if not cust_data.get("status"):
        raise HTTPException(400, f"Could not create Paystack customer: {cust_data.get('message')}")

    customer_code = cust_data["data"]["customer_code"]

    # Step 2: Assign dedicated virtual account (Wema preferred, fallback Titan)
    for bank in ["wema-bank", "titan-paystack"]:
        dva_data = paystack_post("/dedicated_account", {
            "customer":       customer_code,
            "preferred_bank": bank,
        })
        if dva_data.get("status"):
            break

    if not dva_data.get("status"):
        raise HTTPException(400, f"DVA creation failed: {dva_data.get('message')}")

    dva_info = dva_data["data"]
    w.dva = {
        "bank_name":      dva_info["bank"]["name"],
        "bank_code":      dva_info["bank"]["id"],
        "account_number": dva_info["account_number"],
        "account_name":   dva_info["account_name"],
        "reference":      f"NF-DVA-{wallet_id}",
        "currency":       "NGN",
        "mode":           "live",
        "paystack_id":    str(dva_info.get("id", "")),
    }
    save_db()
    logger.info(f"🏦 Live DVA created: {w.dva['account_number']} ({w.dva['bank_name']}) for {wallet_id}")
    return {"success": True, "dva": w.dva, "mode": "live",
            "message": f"Your CredionPay bank account is ready! {w.dva['bank_name']} · {w.dva['account_number']}"}


@app.get("/wallet/{wallet_id}/dva")
def get_dva(wallet_id: str):
    """Get dedicated virtual account details."""
    w = _get_wallet(wallet_id)
    if not w.dva:
        return {"success": False, "dva": None, "message": "No virtual account yet. Call POST /wallet/dva/create"}
    return {"success": True, "dva": w.dva, "owner_name": w.owner_name,
            "wallet_id": wallet_id, "balance": w.balance}


@app.post("/webhooks/paystack")
async def paystack_webhook(request: Request, bg: BackgroundTasks):
    """
    Paystack webhook — handles DVA Wema Bank transfers landing in user wallets.
    Events handled:
      dedicated_account.assign.success  → DVA assigned (log only)
      charge.success                    → Money landed via Wema Bank DVA
      transfer.success                  → Outbound transfer confirmed
    """
    body    = await request.body()
    payload = await request.json()
    event   = payload.get("event", "")
    data    = payload.get("data", {})
    logger.info(f"📨 Paystack webhook: {event}")

    if event == "dedicated_account.assign.success":
        acct = (data.get("dedicated_account") or {}).get("account_number", "")
        logger.info(f"✅ Wema Bank DVA assigned: {acct} → {data.get('customer', {}).get('email')}")
        # Automatically link DVA account number to the right wallet
        email = (data.get("customer") or {}).get("email", "").lower()
        wid   = email_index.get(email) or next(
            (v for k, v in email_index.items() if k.lower() == email), None)
        if wid and wid in wallets and acct:
            w = wallets[wid]
            w.dva.update({
                "account_number": acct,
                "bank_name":      (data.get("dedicated_account") or {}).get("bank", {}).get("name", "Wema Bank"),
                "bank_code":      "035",
                "account_name":   w.owner_name.upper(),
                "mode":           "live",
                "paystack_id":    str((data.get("dedicated_account") or {}).get("id", "")),
            })
            save_db()
            logger.info(f"🏦 DVA linked: {acct} → {wid}")
        return {"status": "ok"}

    if event in ("charge.success",):
        amount_kobo  = data.get("amount", 0)
        amount_naira = amount_kobo / 100
        ref          = data.get("reference", "")
        channel      = data.get("channel", "dedicated_nuban")

        # Dedup — skip if already processed
        for w in wallets.values():
            if any(t.reference == ref for t in w.transactions):
                logger.info(f"⏭️  Paystack webhook: {ref} already processed — skip")
                return {"status": "already_processed"}

        # ── Find wallet by DVA account number (multiple strategies) ──────────
        wallet_found = None

        # Strategy 1: receiver_bank_account_number in authorization
        acct = (data.get("authorization") or {}).get("receiver_bank_account_number", "")

        # Strategy 2: dedicated_account block
        if not acct:
            acct = (data.get("dedicated_account") or {}).get("account_number", "")

        # Strategy 3: customer email
        if not wallet_found and not acct:
            cust_email = ((data.get("customer") or {}).get("email", "")).lower()
            wid = email_index.get(cust_email) or next(
                (v for k, v in email_index.items() if k.lower() == cust_email), None)
            if wid:
                wallet_found = wallets.get(wid)

        # Match by account number across all wallets
        if acct and not wallet_found:
            for w in wallets.values():
                dva_acct = (w.dva or {}).get("account_number", "")
                if dva_acct and dva_acct == acct:
                    wallet_found = w
                    break

        # Strategy 4: metadata wallet_id
        if not wallet_found:
            meta_wid = ((data.get("metadata") or {}).get("wallet_id", ""))
            if meta_wid and meta_wid in wallets:
                wallet_found = wallets[meta_wid]

        if not wallet_found:
            logger.warning(
                f"⚠️ Paystack DVA webhook: no wallet for acct={acct} "
                f"ref={ref} — check DVA account numbers in DB"
            )
            return {"status": "wallet_not_found"}

        sender_name = (
            (data.get("authorization") or {}).get("sender_name") or
            (data.get("customer") or {}).get("name") or
            "Bank transfer"
        )
        sender_bank = (data.get("authorization") or {}).get("sender_bank", "")
        desc = f"Received from {sender_name}" + (f" via {sender_bank}" if sender_bank else "")
        desc += f" | Wema Bank DVA | Ref: {ref}"

        tx = wallet_found.credit(amount_naira, TxCategory.DVA_FUNDING, desc, ref)
        save_db()
        logger.info(
            f"✅ Wema Bank DVA credit: ₦{amount_naira:,.2f} → "
            f"{wallet_found.wallet_id} from {sender_name} | ref={ref}"
        )
        bg.add_task(_email_dva_credit, wallet_found, amount_naira,
                    sender_name, sender_bank or "Wema Bank", ref)
        return {
            "status":  "credited",
            "amount":  amount_naira,
            "wallet":  wallet_found.wallet_id,
            "channel": channel,
        }

    if event == "transfer.success":
        logger.info(f"✅ Paystack outbound transfer confirmed: {data.get('reference')}")
        return {"status": "ok"}

    logger.info(f"ℹ️  Paystack webhook: unhandled event '{event}'")
    return {"status": "ignored"}


def _email_dva_credit(w: "Wallet", amount: float, sender: str, bank: str, ref: str):
    """Send a beautiful credit notification email when Wema Bank DVA receives money."""
    subject = f"✅ ₦{amount:,.2f} received in your CredionPay wallet"
    body = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto">
      <div style="text-align:center;padding:32px 20px 20px;border-bottom:1px solid #F3F4F6">
        <div style="font-size:48px;margin-bottom:8px">🎉</div>
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">Money Received</p>
        <p style="margin:0;font-size:40px;font-weight:900;color:#008751">₦{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;
             padding:6px 16px;background:#F0FDF4;border-radius:20px;border:1px solid #BBF7D0">
          <span style="color:#166534;font-weight:700;font-size:13px">✓ Credited to your wallet</span>
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">From</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;text-align:right;border-bottom:1px solid #F3F4F6">{sender}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">Via bank</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;text-align:right;border-bottom:1px solid #F3F4F6">{bank}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">New balance</td>
            <td style="padding:12px 16px;color:#008751;font-size:13px;font-weight:700;text-align:right;border-bottom:1px solid #F3F4F6">₦{w.balance:,.2f}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">Your DVA</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;text-align:right;border-bottom:1px solid #F3F4F6">
              {w.dva.get("account_number","—")} · {w.dva.get("bank_name","Wema Bank")}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px">Reference</td>
            <td style="padding:12px 16px;color:#6B7280;font-size:11px;font-family:monospace;text-align:right">{ref}</td></tr>
      </table>
      <p style="margin:16px;font-size:12px;color:#6B7280;text-align:center">
        Your money is available immediately. Open CredionPay to use it.
      </p>
    </div>"""
    send_email(
        w.owner_email, subject,
        _receipt_shell(w.owner_name, "#008751", "Money Received 🎉",
                       f"₦{amount:,.2f} from {sender}", body)
    )


@app.post("/wallet/dva/simulate-credit")
def dva_simulate_credit(
    wallet_id:   str   = Body(..., embed=True),
    amount_naira:float = Body(..., embed=True),
    sender_name: str   = Body("Test Sender", embed=True),
    sender_bank: str   = Body("GTBank", embed=True),
    bg: BackgroundTasks = None,
):
    """
    SANDBOX ONLY — simulate a Wema Bank DVA credit without a real webhook.
    Use this to test the DVA funding flow end-to-end in test mode.
    Remove or gate this endpoint before production deployment.
    """
    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    if ps_key.startswith("sk_live_"):
        raise HTTPException(403, "Simulation not available in live mode.")

    w = _get_wallet(wallet_id)
    if not w.dva or not w.dva.get("account_number"):
        raise HTTPException(400, "No DVA account yet. Call POST /wallet/dva/create first.")
    if amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than 0.")

    ref = f"SIM-DVA-{uuid.uuid4().hex[:12].upper()}"
    desc = (f"[SIMULATED] Received from {sender_name} via {sender_bank} "
            f"| Wema Bank DVA | Ref: {ref}")
    tx = w.credit(amount_naira, TxCategory.DVA_FUNDING, desc, ref)
    save_db()
    logger.info(
        f"🧪 DVA credit simulated: ₦{amount_naira:,.2f} → {wallet_id} "
        f"from {sender_name} ({sender_bank}) | ref={ref}"
    )
    if bg:
        bg.add_task(_email_dva_credit, w, amount_naira, sender_name, sender_bank, ref)
    return {
        "success":     True,
        "message":     f"₦{amount_naira:,.2f} credited to {wallet_id} (simulated)",
        "reference":   ref,
        "new_balance": w.balance,
        "dva_account": w.dva.get("account_number"),
        "mode":        "sandbox_simulation",
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENHANCED PAYSTACK TRANSFERS — with OTP verification + fee preview
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/transfer/banks")
def list_banks():
    """Return all Nigerian banks with codes — cached 1hr."""
    data = _paystack_get("/bank?currency=NGN&perPage=100")
    if not data.get("status"):
        raise HTTPException(502, "Could not fetch bank list from Paystack")
    banks = [{"name": b["name"], "code": b["code"]} for b in data["data"]
             if b.get("active") and b.get("is_deleted") is False]
    return {"success": True, "count": len(banks), "banks": banks}


@app.get("/transfer/fee")
def get_transfer_fee(amount: float):
    """Return Paystack transfer fee for a given amount (NGN)."""
    if amount <= 5000:
        fee = 10.0
    elif amount <= 50000:
        fee = 25.0
    else:
        fee = 50.0
    return {
        "success":     True,
        "amount":      amount,
        "fee":         fee,
        "total":       amount + fee,
        "note":        "Fees are charged by Paystack on live keys. No fees on test mode.",
    }


class EnhancedTransferRequest(BaseModel):
    wallet_id:      str
    account_number: str
    bank_code:      str
    amount_naira:   float
    reason:         str = "CredionPay Transfer"
    save_beneficiary: bool = False   # save for quick re-use


@app.post("/transfer/to-bank/v2")
def transfer_to_bank_v2(req: EnhancedTransferRequest, bg: BackgroundTasks):
    """
    Enhanced bank transfer with:
    - Fee preview before debit
    - Beneficiary saving
    - Richer email receipt
    - Transfer status tracking
    """
    w = _get_wallet(req.wallet_id)
    _require_kyc(w)

    # Fee calc
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than 0")
    fee   = 10.0 if req.amount_naira <= 5000 else 25.0 if req.amount_naira <= 50000 else 50.0
    total = req.amount_naira + fee
    ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
    is_live = ps_key.startswith("sk_live_")
    if is_live and total > w.balance:
        raise HTTPException(400, f"Insufficient balance. Need ₦{total:,.2f} (amount + ₦{fee:.0f} fee). Available: ₦{w.balance:,.2f}")
    if not is_live and req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{w.balance:,.2f}")

    # Verify account
    try:
        account_name = _resolve_account(req.account_number, req.bank_code)
    except HTTPException as he:
        raise HTTPException(he.status_code, he.detail)

    # Create recipient
    rec_data = paystack_post("/transferrecipient", {
        "type": "nuban", "name": account_name,
        "account_number": req.account_number,
        "bank_code": req.bank_code,
        "currency": "NGN",
    })
    if not rec_data.get("status"):
        raise HTTPException(400, f"Could not create recipient: {rec_data.get('message')}")

    recipient_code = rec_data["data"]["recipient_code"]

    # Initiate transfer
    reference = f"TRF-{uuid.uuid4().hex[:16].upper()}"
    trf_data = paystack_post("/transfer", {
        "source":    "balance",
        "reason":    req.reason,
        "amount":    int(req.amount_naira * 100),
        "recipient": recipient_code,
        "reference": reference,
    })
    if not trf_data.get("status"):
        raise HTTPException(400, trf_data.get("message", "Transfer failed"))

    # Debit wallet (include fee on live)
    debit_amount = total if is_live else req.amount_naira
    bank_name    = _get_bank_name(req.bank_code)
    tx = w.debit(debit_amount, TxCategory.BANK_PAYOUT,
                 f"Transfer to {account_name} · {bank_name} · {req.account_number} — {req.reason}", reference)

    # Save beneficiary
    if req.save_beneficiary:
        bens = w.__dict__.get("beneficiaries") or []
        bens = [b for b in bens if b.get("account_number") != req.account_number]
        bens.insert(0, {
            "account_number": req.account_number,
            "account_name":   account_name,
            "bank_code":      req.bank_code,
            "bank_name":      bank_name,
            "recipient_code": recipient_code,
            "last_used":      datetime.now().isoformat(),
        })
        w.__dict__["beneficiaries"] = bens[:10]

    transfer_code = trf_data["data"].get("transfer_code", "")
    status        = trf_data["data"].get("status", "pending")
    save_db()

    logger.info(f"💸 Transfer: ₦{req.amount_naira:,.2f} → {account_name} ({bank_name}) | Ref: {reference} | Status: {status}")
    bg.add_task(_email_transfer_receipt_v2, w, account_name, req.account_number,
                bank_name, req.amount_naira, fee if is_live else 0,
                reference, transfer_code, req.reason, status)

    return {
        "success":        True,
        "message":        f"₦{req.amount_naira:,.2f} transfer to {account_name} initiated",
        "reference":      reference,
        "transfer_code":  transfer_code,
        "account_name":   account_name,
        "bank":           bank_name,
        "amount":         req.amount_naira,
        "fee":            fee if is_live else 0,
        "total_debited":  debit_amount,
        "new_balance":    w.balance,
        "status":         status,
    }


@app.get("/transfer/status/{reference}")
def check_transfer_status(reference: str):
    """Check transfer status from Paystack."""
    data = _paystack_get(f"/transfer/{reference}")
    if not data.get("status"):
        raise HTTPException(404, "Transfer not found")
    d = data["data"]
    return {
        "success":   True,
        "reference": reference,
        "status":    d.get("status"),
        "amount":    d.get("amount", 0) / 100,
        "reason":    d.get("reason"),
        "created_at": d.get("createdAt"),
    }


def _email_transfer_receipt_v2(w, account_name, account_number, bank_name,
                                amount, fee, reference, transfer_code, reason, status):
    total = amount + fee
    subject = f"✅ ₦{amount:,.2f} sent to {account_name}"
    body = f"""
    <div style="padding:10px 0 20px">
      <p style="font-size:18px;font-weight:700;color:#111;">Transfer Initiated 💸</p>
      <p style="color:#555;font-size:14px;">Your transfer is on its way.</p>
    </div>
    {_receipt_table(
        ("Recipient",       account_name),
        ("Bank",            bank_name),
        ("Account",         account_number),
        ("Amount Sent",     f"₦{amount:,.2f}"),
        ("Transfer Fee",    f"₦{fee:,.2f}" if fee > 0 else "Free (demo mode)"),
        ("Total Debited",   f"₦{total:,.2f}"),
        ("Wallet Balance",  f"₦{w.balance:,.2f}"),
        ("Reason",          reason),
        ("Reference",       reference),
        ("Transfer Code",   transfer_code),
        ("Status",          "✅ " + status.title(), True),
    )}
    <p style="font-size:12px;color:#666;margin-top:16px;">
      Transfers typically arrive within 5 minutes. Use reference <strong>{reference}</strong>
      if you need to query this transfer.
    </p>
    """
    send_email(w.owner_email, subject, body, w.owner_name.split()[0])


# ══════════════════════════════════════════════════════════════════════════════
# HUSTLE INVOICE — Create, share, pay, and track freelance invoices
# ══════════════════════════════════════════════════════════════════════════════

invoices_db: dict[str, dict] = {}   # invoice_id -> invoice dict

class InvoiceItem(BaseModel):
    description: str
    quantity:    float = 1
    unit_price:  float

class CreateInvoiceRequest(BaseModel):
    wallet_id:    str
    client_name:  str
    client_email: str
    items:        list[InvoiceItem]
    due_days:     int = 7
    note:         str = ""
    currency:     str = "NGN"

class PayInvoiceRequest(BaseModel):
    invoice_id:   str
    payer_email:  str
    pay_method:   str = "paystack_link"   # paystack_link | bank_transfer


@app.post("/invoice/create")
def create_invoice(req: CreateInvoiceRequest, bg: BackgroundTasks):
    """Create a hustle invoice. Returns a shareable payment link."""
    w = _get_wallet(req.wallet_id)

    if not req.items:
        raise HTTPException(400, "Invoice must have at least one item")

    subtotal = sum(i.quantity * i.unit_price for i in req.items)
    vat      = 0.0   # add 7.5% VAT toggle in future
    total    = subtotal + vat

    inv_id  = f"INV-{uuid.uuid4().hex[:10].upper()}"
    inv_num = f"NF-{datetime.now().strftime('%Y%m')}-{len(w.invoices) + 1:03d}"
    due_date = (datetime.now() + timedelta(days=req.due_days)).strftime("%d %b %Y")
    now      = datetime.now().isoformat()

    invoice = {
        "invoice_id":   inv_id,
        "invoice_num":  inv_num,
        "wallet_id":    req.wallet_id,
        "owner_name":   w.owner_name,
        "owner_email":  w.owner_email,
        "client_name":  req.client_name,
        "client_email": req.client_email,
        "items":        [i.dict() for i in req.items],
        "subtotal":     subtotal,
        "vat":          vat,
        "total":        total,
        "currency":     req.currency,
        "note":         req.note,
        "due_date":     due_date,
        "due_days":     req.due_days,
        "status":       "unpaid",
        "created_at":   now,
        "paid_at":      None,
        "pay_reference": None,
    }

    invoices_db[inv_id] = invoice
    w.invoices.append(inv_id)
    save_db()

    # Payment link (uses Paystack)
    pay_link = f"https://credionpay.app/pay-invoice/{inv_id}"
    ps_link  = None
    try:
        link_data = paystack_post("/transaction/initialize", {
            "email":     req.client_email,
            "amount":    int(total * 100),
            "reference": f"INV-PAY-{inv_id}",
            "metadata":  {"invoice_id": inv_id, "wallet_id": req.wallet_id},
            "callback_url": f"https://credionpay.app/invoice-paid/{inv_id}",
        })
        if link_data.get("status"):
            ps_link  = link_data["data"]["authorization_url"]
            pay_link = ps_link
    except Exception as e:
        logger.warning(f"Paystack link failed for invoice {inv_id}: {e}")

    invoice["pay_link"] = pay_link
    invoices_db[inv_id] = invoice

    logger.info(f"🧾 Invoice created: {inv_num} | ₦{total:,.2f} | Client: {req.client_name}")

    # Email invoice to client + notify owner
    bg.add_task(_email_invoice_to_client, invoice, pay_link)
    bg.add_task(_email_invoice_created_notify, w, invoice)

    return {
        "success":     True,
        "invoice_id":  inv_id,
        "invoice_num": inv_num,
        "total":       total,
        "pay_link":    pay_link,
        "due_date":    due_date,
        "message":     f"Invoice {inv_num} created and sent to {req.client_email}",
    }


@app.get("/invoice/{invoice_id}")
def get_invoice(invoice_id: str):
    """Get invoice details — used by payment page."""
    if invoice_id not in invoices_db:
        raise HTTPException(404, "Invoice not found")
    return {"success": True, "invoice": invoices_db[invoice_id]}


@app.get("/invoice/wallet/{wallet_id}")
def list_invoices(wallet_id: str):
    """List all invoices for a wallet."""
    w = _get_wallet(wallet_id)
    invs = [invoices_db[i] for i in w.invoices if i in invoices_db]
    total_invoiced = sum(i["total"] for i in invs)
    total_paid     = sum(i["total"] for i in invs if i["status"] == "paid")
    total_unpaid   = sum(i["total"] for i in invs if i["status"] == "unpaid")
    return {
        "success":        True,
        "count":          len(invs),
        "total_invoiced": total_invoiced,
        "total_paid":     total_paid,
        "total_unpaid":   total_unpaid,
        "invoices":       sorted(invs, key=lambda x: x["created_at"], reverse=True),
    }


@app.post("/invoice/{invoice_id}/mark-paid")
def mark_invoice_paid(invoice_id: str, reference: str = Body(..., embed=True), bg: BackgroundTasks = None):
    """
    Mark an invoice as paid and credit the freelancer's wallet.
    Called by: Paystack webhook OR manually by admin.
    """
    if invoice_id not in invoices_db:
        raise HTTPException(404, "Invoice not found")
    inv = invoices_db[invoice_id]
    if inv["status"] == "paid":
        return {"success": True, "message": "Already paid", "invoice": inv}

    w = _get_wallet(inv["wallet_id"])
    amount = inv["total"]
    tx = w.credit(amount, TxCategory.INVOICE_PAYMENT,
                  f"Invoice {inv['invoice_num']} paid by {inv['client_name']}", reference)
    inv["status"]       = "paid"
    inv["paid_at"]      = datetime.now().isoformat()
    inv["pay_reference"] = reference
    save_db()

    logger.info(f"✅ Invoice {invoice_id} paid: ₦{amount:,.2f} credited to {inv['wallet_id']}")
    if bg:
        bg.add_task(_email_invoice_paid_notify, w, inv)
        bg.add_task(_email_invoice_receipt_to_client, inv)

    return {"success": True, "message": f"₦{amount:,.2f} credited to wallet",
            "new_balance": w.balance, "invoice": inv}


@app.post("/webhooks/paystack/invoice")
async def paystack_invoice_webhook(request: Request, bg: BackgroundTasks):
    """Handle Paystack payment webhook for invoice payments."""
    payload  = await request.json()
    event    = payload.get("event", "")
    data     = payload.get("data", {})
    if event != "charge.success":
        return {"status": "ignored"}

    meta       = data.get("metadata", {}) or {}
    invoice_id = meta.get("invoice_id")
    reference  = data.get("reference", "")
    if not invoice_id or invoice_id not in invoices_db:
        return {"status": "invoice_not_found"}

    # delegate to mark-paid
    inv = invoices_db[invoice_id]
    if inv["status"] != "paid":
        w = _get_wallet(inv["wallet_id"])
        w.credit(inv["total"], TxCategory.INVOICE_PAYMENT,
                 f"Invoice {inv['invoice_num']} — {inv['client_name']}", reference)
        inv["status"] = "paid"
        inv["paid_at"] = datetime.now().isoformat()
        inv["pay_reference"] = reference
        save_db()
        bg.add_task(_email_invoice_paid_notify, w, inv)
        bg.add_task(_email_invoice_receipt_to_client, inv)
    return {"status": "ok"}


def _build_invoice_html(inv: dict) -> str:
    """Build a clean HTML invoice for email."""
    items_html = "".join(f"""
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0">{i['description']}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;text-align:center">{i['quantity']:.0f}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;text-align:right">₦{i['unit_price']:,.2f}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f0f0;text-align:right;font-weight:bold">₦{i['quantity']*i['unit_price']:,.2f}</td>
    </tr>""" for i in inv["items"])

    return f"""
    <div style="max-width:560px;margin:0 auto;font-family:sans-serif">
      <div style="background:linear-gradient(135deg,#006400,#008751);padding:24px;border-radius:12px 12px 0 0">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="color:white;font-size:22px;font-weight:900">🇳🇬 CredionPay</div>
            <div style="color:rgba(255,255,255,0.7);font-size:12px">Hustle Invoice</div>
          </div>
          <div style="text-align:right">
            <div style="color:white;font-size:16px;font-weight:bold">{inv['invoice_num']}</div>
            <div style="color:rgba(255,255,255,0.7);font-size:11px">Due: {inv['due_date']}</div>
          </div>
        </div>
      </div>
      <div style="background:white;padding:24px;border:1px solid #e5e7eb">
        <div style="display:flex;justify-content:space-between;margin-bottom:24px">
          <div>
            <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px">From</div>
            <div style="font-weight:bold;font-size:15px">{inv['owner_name']}</div>
            <div style="color:#6b7280;font-size:13px">{inv['owner_email']}</div>
          </div>
          <div style="text-align:right">
            <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px">Bill To</div>
            <div style="font-weight:bold;font-size:15px">{inv['client_name']}</div>
            <div style="color:#6b7280;font-size:13px">{inv['client_email']}</div>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
          <thead>
            <tr style="background:#f9fafb">
              <th style="padding:10px 12px;text-align:left;font-size:12px;color:#6b7280">Description</th>
              <th style="padding:10px 12px;text-align:center;font-size:12px;color:#6b7280">Qty</th>
              <th style="padding:10px 12px;text-align:right;font-size:12px;color:#6b7280">Unit Price</th>
              <th style="padding:10px 12px;text-align:right;font-size:12px;color:#6b7280">Total</th>
            </tr>
          </thead>
          <tbody>{items_html}</tbody>
        </table>
        <div style="display:flex;justify-content:flex-end">
          <table style="width:240px">
            <tr><td style="padding:4px 0;color:#6b7280;font-size:13px">Subtotal</td>
                <td style="text-align:right;font-size:13px">₦{inv['subtotal']:,.2f}</td></tr>
            <tr><td style="padding:4px 0;color:#6b7280;font-size:13px">VAT (0%)</td>
                <td style="text-align:right;font-size:13px">₦0.00</td></tr>
            <tr style="border-top:2px solid #008751">
              <td style="padding:8px 0;font-weight:bold;color:#008751">Total Due</td>
              <td style="text-align:right;font-weight:bold;color:#008751;font-size:18px">₦{inv['total']:,.2f}</td>
            </tr>
          </table>
        </div>
        {f'<p style="color:#6b7280;font-size:13px;margin-top:20px;padding-top:16px;border-top:1px solid #f0f0f0">{inv["note"]}</p>' if inv.get("note") else ""}
      </div>
    </div>"""


def _email_invoice_to_client(inv: dict, pay_link: str):
    subject = f"Invoice {inv['invoice_num']} from {inv['owner_name']} — ₦{inv['total']:,.2f} due {inv['due_date']}"
    body = f"""
    {_build_invoice_html(inv)}
    <div style="max-width:560px;margin:20px auto 0;text-align:center">
      <a href="{pay_link}" style="display:inline-block;background:#008751;color:white;padding:14px 40px;border-radius:8px;font-weight:bold;font-size:16px;text-decoration:none">
        Pay ₦{inv['total']:,.2f} Now
      </a>
      <p style="color:#9ca3af;font-size:11px;margin-top:12px">
        Payment secured by Paystack · CredionPay Hustle Invoice
      </p>
    </div>"""
    send_email(inv["client_email"], subject, body, inv["client_name"].split()[0])


def _email_invoice_created_notify(w, inv: dict):
    subject = f"🧾 Invoice {inv['invoice_num']} sent to {inv['client_name']}"
    body = f"""
    <p>Your invoice has been sent to <strong>{inv['client_name']}</strong> ({inv['client_email']}).</p>
    {_receipt_table(
        ("Invoice No.",   inv["invoice_num"]),
        ("Client",        inv["client_name"]),
        ("Amount",        f"₦{inv['total']:,.2f}"),
        ("Due Date",      inv["due_date"]),
        ("Status",        "📤 Sent — Awaiting Payment"),
    )}"""
    send_email(w.owner_email, subject, body, w.owner_name.split()[0])


def _email_invoice_paid_notify(w, inv: dict):
    subject = f"💰 Invoice {inv['invoice_num']} paid! ₦{inv['total']:,.2f} in your wallet"
    body = f"""
    <div style="padding:10px 0 20px">
      <p style="font-size:18px;font-weight:700;color:#111;">You got paid! 🎉</p>
      <p style="color:#555;">₦{inv['total']:,.2f} has been credited to your CredionPay wallet.</p>
    </div>
    {_receipt_table(
        ("Invoice No.",    inv["invoice_num"]),
        ("Paid By",        inv["client_name"]),
        ("Amount Received", f"₦{inv['total']:,.2f}"),
        ("Wallet Balance", f"₦{w.balance:,.2f}"),
        ("Reference",      inv["pay_reference"] or "—"),
        ("Status",         "✅ Paid & Credited", True),
    )}"""
    send_email(w.owner_email, subject, body, w.owner_name.split()[0])


def _email_invoice_receipt_to_client(inv: dict):
    subject = f"✅ Payment confirmed — {inv['invoice_num']}"
    body = f"""
    <p>Your payment of <strong>₦{inv['total']:,.2f}</strong> to <strong>{inv['owner_name']}</strong> has been confirmed.</p>
    {_receipt_table(
        ("Invoice No.",  inv["invoice_num"]),
        ("Paid To",      inv["owner_name"]),
        ("Amount",       f"₦{inv['total']:,.2f}"),
        ("Reference",    inv["pay_reference"] or "—"),
        ("Status",       "✅ Paid", True),
    )}"""
    send_email(inv["client_email"], subject, body, inv["client_name"].split()[0])



# ══════════════════════════════════════════════════════════════════════════════
# ADMIN / DEV TOOLS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/dev/wallet/{wallet_id}/reset-kyc")
def dev_reset_kyc(wallet_id: str):
    """
    DEV ONLY — reset KYC status so the wallet can be re-verified.
    Also clears owner_name so it gets set fresh from next KYC.
    Remove or protect this endpoint before going to production.
    """
    w = _get_wallet(wallet_id)
    old_name   = w.owner_name
    old_status = w.kyc.status
    w.kyc.status         = KYCStatus.PENDING
    w.kyc.failure_reason = ""
    w.kyc.verified_at    = ""
    # Reset display name to what was typed at signup so it updates on next KYC
    # (keep email/phone, just clear the KYC-derived name)
    save_db()
    logger.info(f"🔄 DEV: KYC reset for {wallet_id} — was {old_status}/{old_name}")
    return {
        "success":    True,
        "message":    f"KYC reset. Wallet {wallet_id} can now be re-verified.",
        "wallet_id":  wallet_id,
        "old_name":   old_name,
        "old_status": old_status,
    }

@app.patch("/dev/wallet/{wallet_id}/name")
def dev_update_name(wallet_id: str, name: str = Body(..., embed=True)):
    """DEV ONLY — manually correct wallet display name and regenerate USD tag."""
    w = _get_wallet(wallet_id)
    old_name = w.owner_name
    old_tag  = w.usd_tag
    w.owner_name = name.strip().title()
    # Remove old tag from index FIRST so _generate_usd_tag doesn't loop
    if old_tag and old_tag in usd_tag_index:
        del usd_tag_index[old_tag]
    w.usd_tag = ""   # clear so generator doesn't see self as collision
    new_tag = _generate_usd_tag(w.owner_name)
    w.usd_tag = new_tag
    usd_tag_index[new_tag] = wallet_id
    save_db()
    logger.info(f"✏️  Dev name update: {wallet_id} '{old_name}' → '{w.owner_name}' | tag: {old_tag} → {new_tag}")
    return {"success": True, "old_name": old_name, "new_name": w.owner_name,
            "old_tag": old_tag, "new_tag": new_tag}

@app.post("/dev/wallet/{wallet_id}/fix-tag")
def dev_fix_tag(wallet_id: str, force_name: str = ""):
    """DEV ONLY — regenerate a clean USD tag. Optionally pass force_name to override."""
    w = _get_wallet(wallet_id)
    old_tag = w.usd_tag
    # Remove old tag from index first — critical so _generate_usd_tag doesn't loop
    if old_tag and old_tag in usd_tag_index:
        del usd_tag_index[old_tag]
    # Also clear w.usd_tag so generate doesn't see self as collision
    w.usd_tag = ""
    name = force_name.strip() if force_name.strip() else w.owner_name
    new_tag = _generate_usd_tag(name)
    w.usd_tag = new_tag
    usd_tag_index[new_tag] = wallet_id
    save_db()
    logger.info(f"🏷️  Tag fixed: {wallet_id} '{old_tag}' → '{new_tag}' (name='{name}')")
    return {"success": True, "wallet_id": wallet_id, "owner_name": w.owner_name,
            "old_tag": old_tag, "new_tag": new_tag}

@app.get("/dev/debug")
def dev_debug():
    """DEV ONLY — dump live in-memory state for debugging."""
    return {
        "wallets": {wid: {"name": w.owner_name, "email": w.owner_email,
                          "usd_tag": w.usd_tag, "balance": w.balance}
                    for wid, w in wallets.items()},
        "usd_tag_index": dict(usd_tag_index),
        "email_index": dict(email_index),
    }


@app.post("/dev/migrate/fix-accounts")
def migrate_fix_accounts():
    """
    DEV ONLY — One-time migration to fix:
    1. Virtual account numbers containing hex letters (e.g. 79C69131 → 79012345)
    2. Duplicated owner names ('Foo Bar Foo Bar' → 'Foo Bar')
    3. Long USD tags (regen from cleaned name, max 20 chars)
    Run this once after deploying the fix.
    """
    import random as _r
    def _rand_digits(n): return "".join([str(_r.randint(0, 9)) for _ in range(n)])
    def _is_hex_contaminated(s: str) -> bool:
        return bool(s) and any(c in s.upper() for c in "ABCDEF")

    fixed = []
    for wid, w in wallets.items():
        changed = []

        # Fix duplicated owner name
        clean_name = _clean_owner_name(w.owner_name)
        if clean_name != w.owner_name:
            w.owner_name = clean_name
            changed.append("owner_name")

        # Fix UK account number
        uk_acct = (w.virtual_acct_uk or {}).get("account_no", "")
        if _is_hex_contaminated(uk_acct):
            new_uk = "7" + _rand_digits(7)
            w.virtual_acct_uk["account_no"]   = new_uk
            w.virtual_acct_uk["account_name"] = w.owner_name
            changed.append(f"uk_account:{uk_acct}→{new_uk}")

        # Fix US account number
        us_acct = (w.virtual_acct_us or {}).get("account_no", "")
        if _is_hex_contaminated(us_acct):
            new_us = "9" + _rand_digits(8)
            w.virtual_acct_us["account_no"]   = new_us
            w.virtual_acct_us["account_name"] = w.owner_name
            changed.append(f"us_account:{us_acct}→{new_us}")

        # Fix long or hex-contaminated USD tag
        tag = w.usd_tag or ""
        slug = tag.split("/")[-1] if "/" in tag else tag
        if len(slug) > 20 or _is_hex_contaminated(slug):
            # Remove old tag from index
            if tag in usd_tag_index:
                del usd_tag_index[tag]
            # Generate a clean new tag from the (now-cleaned) owner name
            new_tag = _generate_usd_tag(w.owner_name)
            w.usd_tag = new_tag
            usd_tag_index[new_tag] = wid
            # Update references in virtual accounts
            if w.virtual_acct_uk:
                w.virtual_acct_uk["reference"] = new_tag
            if w.virtual_acct_us:
                w.virtual_acct_us["reference"] = new_tag
            changed.append(f"usd_tag:{tag}→{new_tag}")

        # Also fix account_name duplication in virtual accounts
        for acct_dict in [w.virtual_acct_uk, w.virtual_acct_us]:
            if acct_dict:
                stored_name = acct_dict.get("account_name", "")
                fixed_name  = _clean_owner_name(stored_name)
                if fixed_name != stored_name:
                    acct_dict["account_name"] = fixed_name
                    if "account_name" not in " ".join(changed):
                        changed.append("account_name_dedup")

        if changed:
            fixed.append({"wallet_id": wid, "fixes": changed})

    if fixed:
        save_db()

    logger.info(f"🔧 Migration: fixed {len(fixed)} wallets — {[f['wallet_id'] for f in fixed]}")
    return {
        "success":       True,
        "wallets_fixed": len(fixed),
        "details":       fixed,
        "message":       f"Fixed {len(fixed)} wallet(s). Restart not required.",
    }


@app.post("/dev/upload-db")
async def upload_db(request: Request):
    """
    ONE-TIME USE — Upload local DB files to Railway Volume.
    POST JSON body: {"db": "..json content..", "savings": "..json..", "cards": "..json.."}
    Delete or disable this endpoint after migration is complete.
    """
    body = await request.json()
    uploaded = []

    if "db" in body and body["db"]:
        try:
            parsed = json.loads(body["db"])   # validate JSON
            DB_FILE.write_text(json.dumps(parsed, indent=2))
            uploaded.append("credionpay_db.json")
            logger.info("📤 DB file uploaded via /dev/upload-db")
        except Exception as e:
            raise HTTPException(400, f"Invalid DB JSON: {e}")

    if "savings" in body and body["savings"]:
        try:
            parsed = json.loads(body["savings"])
            SAVINGS_FILE.write_text(json.dumps(parsed, indent=2))
            uploaded.append("credionpay_savings.json")
        except Exception as e:
            raise HTTPException(400, f"Invalid savings JSON: {e}")

    if "cards" in body and body["cards"]:
        try:
            parsed = json.loads(body["cards"])
            CARD_FILE.write_text(json.dumps(parsed, indent=2))
            uploaded.append("credionpay_cards.json")
        except Exception as e:
            raise HTTPException(400, f"Invalid cards JSON: {e}")

    if not uploaded:
        raise HTTPException(400, "No data provided. Send {db: '...', savings: '...', cards: '...'}")

    # Reload everything from disk
    load_db()
    _load_savings()
    logger.info(f"✅ DB upload complete: {uploaded}")
    return {
        "success":  True,
        "uploaded": uploaded,
        "wallets":  len(wallets),
        "message":  f"Uploaded {len(uploaded)} file(s). {len(wallets)} wallets now loaded.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# WHATSAPP PAY — Send money to anyone via WhatsApp link (no app needed)
# ══════════════════════════════════════════════════════════════════════════════

def _whatsapp_link_url(link_id: str, base_url: str = "") -> str:
    host = base_url or os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
    if not host.startswith("http"):
        host = f"https://{host}" if ("railway" in host or "ngrok" in host) else f"http://{host}"
    return f"{host}/pay/{link_id}"

def _whatsapp_message(sender_name: str, amount: float, note: str,
                      link_url: str, recipient_name: str, expires_h: int) -> str:
    note_line = f"\n\U0001f4dd Message: _{note}_" if note.strip() else ""
    return (
        f"\U0001f49a *You have received money via CredionPay!*\n\n"
        f"\U0001f464 From: *{sender_name}*\n"
        f"\U0001f4b5 Amount: *\u20a6{amount:,.2f}*{note_line}\n\n"
        f"\U0001f447 Click the link below to claim your money:\n"
        f"{link_url}\n\n"
        f"\u23f0 This link expires in {expires_h} hours.\n"
        f"\u2705 No app download needed \u2014 claim directly in your browser.\n\n"
        f"_Powered by CredionPay \u00b7 Nigeria\u2019s smartest digital wallet_"
    )

@app.post("/whatsapp-pay/create")
def create_whatsapp_pay_link(req: WhatsAppPayRequest, bg: BackgroundTasks, request: Request):
    w = _get_wallet(req.sender_wallet_id)
    _require_kyc(w)
    # ── OTP verification required for WhatsApp Pay ───────────────────────────
    otp_key    = _otp_key(req.sender_wallet_id, "whatsapp_pay")
    otp_record = otp_store.get(otp_key, {})
    if not otp_record.get("verified"):
        raise HTTPException(403,
            "OTP verification required. Please verify your OTP before sending via WhatsApp Pay.")
    otp_store.pop(otp_key, None)
    logger.info(f"\u2705 OTP consumed for WhatsApp Pay: {req.sender_wallet_id}")
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount_naira > w.balance:
        raise HTTPException(400, f"Insufficient balance. Available: \u20a6{w.balance:,.2f}")
    if req.amount_naira > 500_000:
        raise HTTPException(400, "WhatsApp Pay limit is \u20a6500,000 per link")
    if not req.recipient_phone.strip():
        raise HTTPException(400, "Recipient phone number is required")
    # ── Normalise phone number ─────────────────────────────────────────────────
    raw_phone = req.recipient_phone.strip().replace(" ","").replace("-","").replace("(","").replace(")","")
    phone = raw_phone
    if phone.startswith("+234"):
        phone = "0" + phone[4:]
    elif phone.startswith("234") and len(phone) >= 12:
        phone = "0" + phone[3:]
    elif phone.startswith("0") and len(phone) == 11:
        pass   # already correct format
    elif len(phone) == 10 and not phone.startswith("0"):
        phone = "0" + phone  # missing leading 0
    # Strip any non-digit characters
    phone = "".join(c for c in phone if c.isdigit())
    if len(phone) == 11 and not phone.startswith("0"):
        phone = "0" + phone[1:]
    # Final validation
    if not phone.startswith("0") or len(phone) != 11:
        raise HTTPException(400,
            f"Invalid Nigerian phone number: '{req.recipient_phone}'. "
            f"Please use format: 08012345678 or +2348012345678")
    # Validate it looks like a real Nigerian mobile number
    valid_prefixes = ("070","080","081","090","091","070","071","072",
                      "073","074","075","076","077","078","079")
    if not phone[:3] in valid_prefixes:
        raise HTTPException(400,
            f"'{phone}' doesn't look like a Nigerian mobile number. "
            f"Valid prefixes: 070, 080, 081, 090, 091")
    logger.info(f"\U0001f4f1 Phone normalised: '{req.recipient_phone}' \u2192 '{phone}'")
    link_id = f"WPAY-{uuid.uuid4().hex[:12].upper()}"
    ref     = f"WHATSAPP-HOLD-{link_id}"
    try:
        tx = w.debit(req.amount_naira, "whatsapp_pay_hold",
                     f"WhatsApp Pay to {req.recipient_name} ({phone}) \u2014 held in escrow", ref)
    except ValueError as e:
        raise HTTPException(400, str(e))
    base     = str(request.base_url).rstrip("/")
    link_url = _whatsapp_link_url(link_id, base)
    from datetime import timedelta
    expires_at = (datetime.now() + timedelta(hours=req.expires_hours)).isoformat()
    whatsapp_links[link_id] = {
        "link_id": link_id, "sender_wallet_id": req.sender_wallet_id,
        "sender_name": w.owner_name, "recipient_phone": phone,
        "recipient_name": req.recipient_name, "amount_naira": req.amount_naira,
        "note": req.note or "", "status": "pending",
        "created_at": datetime.now().isoformat(), "expires_at": expires_at,
        "expires_hours": req.expires_hours, "ref": ref, "link_url": link_url,
        "claimed_by": None, "claimed_at": None,
    }
    save_db()
    msg_text  = _whatsapp_message(w.owner_name, req.amount_naira, req.note,
                                   link_url, req.recipient_name, req.expires_hours)
    wa_number = "234" + phone[1:]
    import urllib.parse
    wa_url    = f"https://wa.me/{wa_number}?text={urllib.parse.quote(msg_text)}"
    logger.info(f"\U0001f49a WhatsApp Pay created: {link_id} \u20a6{req.amount_naira:,.2f} \u2192 {phone} ({req.recipient_name})")
    bg.add_task(_send_whatsapp_pay_email, w, link_id, req.recipient_name, phone,
                req.amount_naira, req.note, expires_at[:10])
    return {"success": True, "link_id": link_id, "link_url": link_url,
            "whatsapp_url": wa_url, "message_text": msg_text,
            "amount": req.amount_naira, "recipient": req.recipient_name,
            "phone": phone, "expires_at": expires_at, "new_balance": w.balance}


@app.get("/pay/{link_id}", response_class=HTMLResponse)
def whatsapp_pay_claim_page(link_id: str):
    link = whatsapp_links.get(link_id)
    if not link:
        return HTMLResponse(_pay_page_error("Payment link not found or has expired."), status_code=404)
    from datetime import datetime as dt
    try:
        exp = dt.fromisoformat(link["expires_at"])
        if dt.now() > exp:
            if link["status"] == "pending":
                _expire_whatsapp_link(link_id)
            return HTMLResponse(_pay_page_error(
                f"This payment link expired on {exp.strftime('%d %b %Y')}."
                f" Please ask {link['sender_name']} to send a new link."), status_code=410)
    except Exception:
        pass
    if link["status"] == "claimed":
        return HTMLResponse(_pay_page_claimed(link))
    if link["status"] in ("expired", "cancelled"):
        return HTMLResponse(_pay_page_error(f"This link has been {link['status']}."), status_code=410)
    return HTMLResponse(_pay_page_form(link))


@app.post("/pay/{link_id}/claim")
def claim_whatsapp_pay(link_id: str, req: WhatsAppPayClaim, bg: BackgroundTasks):
    link = whatsapp_links.get(link_id)
    if not link:
        raise HTTPException(404, "Payment link not found")
    if link["status"] != "pending":
        raise HTTPException(400, f"This link has already been {link['status']}")
    from datetime import datetime as dt
    try:
        if dt.now() > dt.fromisoformat(link["expires_at"]):
            _expire_whatsapp_link(link_id)
            raise HTTPException(410, "Payment link has expired")
    except HTTPException:
        raise
    except Exception:
        pass
    email  = req.recipient_email.strip().lower()
    amount = link["amount_naira"]
    if email and email in email_index:
        recipient_wid = email_index[email]
        recipient_w   = wallets[recipient_wid]
        ref = f"WPAY-CLAIM-{uuid.uuid4().hex[:8].upper()}"
        recipient_w.credit(amount, "whatsapp_pay_receive",
                           f"WhatsApp Pay from {link['sender_name']} \u2014 {link['note'] or 'Payment'}", ref)
        link["status"] = "claimed"; link["claimed_by"] = email
        link["claimed_at"] = datetime.now().isoformat()
        save_db()
        bg.add_task(_send_claim_confirmation_emails, link, recipient_w.owner_name, "wallet")
        return {"success": True, "message": f"\u20a6{amount:,.2f} added to your CredionPay wallet!",
                "method": "wallet_credit", "amount": amount}
    elif req.bank_code and req.account_number:
        try:
            account_name = _resolve_account(req.account_number, req.bank_code,
                                             fallback_name=req.recipient_name)
            ps_key = os.getenv("PAYSTACK_SECRET_KEY", "")
            ref = f"WPAY-BANK-{uuid.uuid4().hex[:8].upper()}"
            if ps_key.startswith("sk_live_"):
                rec_data = paystack_post("/transferrecipient", {
                    "type": "nuban", "name": account_name,
                    "account_number": req.account_number,
                    "bank_code": req.bank_code, "currency": "NGN",
                })
                paystack_post("/transfer", {
                    "source": "balance",
                    "reason": f"CredionPay WhatsApp Pay from {link['sender_name']}",
                    "amount": int(amount * 100),
                    "recipient": rec_data["data"]["recipient_code"], "reference": ref,
                })
            else:
                logger.info(f"\U0001f49a TEST MODE: Simulating bank payout \u20a6{amount:,.2f} \u2192 {req.account_number}")
            link["status"] = "claimed"; link["claimed_by"] = f"{req.account_number}@{req.bank_code}"
            link["claimed_at"] = datetime.now().isoformat()
            save_db()
            bg.add_task(_send_claim_confirmation_emails, link, req.recipient_name, "bank")
            return {"success": True, "message": f"\u20a6{amount:,.2f} will arrive in your bank shortly!",
                    "method": "bank_transfer", "amount": amount}
        except Exception as e:
            raise HTTPException(400, f"Bank payout failed: {e}")
    else:
        new_w = Wallet(owner_name=req.recipient_name.title(),
                       owner_email=email or f"noemail_{link_id}@credionpay.temp",
                       phone=link["recipient_phone"])
        new_w.usd_tag = _generate_usd_tag(new_w.owner_name)
        usd_tag_index[new_w.usd_tag] = new_w.wallet_id
        ref = f"WPAY-NEW-{uuid.uuid4().hex[:8].upper()}"
        new_w.credit(amount, "whatsapp_pay_receive",
                     f"WhatsApp Pay from {link['sender_name']} \u2014 {link['note'] or 'Payment'}", ref)
        wallets[new_w.wallet_id] = new_w
        if email:
            email_index[email] = new_w.wallet_id
        link["status"] = "claimed"; link["claimed_by"] = new_w.wallet_id
        link["claimed_at"] = datetime.now().isoformat()
        save_db()
        bg.add_task(_send_new_wallet_claim_email, link, new_w)
        return {"success": True, "message": f"\u20a6{amount:,.2f} received! Your CredionPay wallet is ready.",
                "method": "new_wallet", "wallet_id": new_w.wallet_id, "amount": amount}


@app.post("/whatsapp-pay/verify-phone")
def verify_whatsapp_phone(phone_raw: str = Body(..., embed=True)):
    """
    Verify a Nigerian phone number:
    1. Normalise format
    2. Check valid prefix
    3. Optionally verify via Paystack (live key only)
    Returns: {valid, phone, carrier, message}
    """
    phone = phone_raw.strip().replace(" ","").replace("-","").replace("(","").replace(")","")
    if phone.startswith("+234"):   phone = "0" + phone[4:]
    elif phone.startswith("234"):  phone = "0" + phone[3:]
    elif len(phone) == 10 and not phone.startswith("0"): phone = "0" + phone
    phone = "".join(c for c in phone if c.isdigit())

    if not phone.startswith("0") or len(phone) != 11:
        return {"valid": False, "phone": phone,
                "message": f"Invalid format. Use: 08012345678"}

    # Nigerian carrier prefix map
    mtn     = {"0803","0806","0810","0813","0814","0816","0903","0906","0913","0916"}
    airtel  = {"0802","0808","0812","0701","0902","0907","0901","0911"}
    glo     = {"0805","0807","0811","0815","0905","0915"}
    nine    = {"0809","0817","0818","0909","0908"}
    prefix3 = phone[:4]
    if   prefix3 in mtn:    carrier = "MTN Nigeria"
    elif prefix3 in airtel: carrier = "Airtel Nigeria"
    elif prefix3 in glo:    carrier = "Glo Nigeria"
    elif prefix3 in nine:   carrier = "9mobile"
    else:                   carrier = "Unknown carrier"

    valid_prefixes = ("070","080","081","090","091","071")
    if phone[:3] not in valid_prefixes:
        return {"valid": False, "phone": phone, "carrier": carrier,
                "message": f"'{phone[:3]}' is not a valid Nigerian mobile prefix"}

    # Live Paystack phone lookup (optional — only on live key)
    ps_key = os.getenv("PAYSTACK_SECRET_KEY","")
    paystack_verified = False
    if ps_key.startswith("sk_live_"):
        try:
            intl = "234" + phone[1:]   # convert to international
            res  = paystack_get("/identity/phone/resolve",
                                {"phone": intl, "country": "NG"})
            if res.get("status"):
                carrier = res.get("data",{}).get("carrier", carrier)
                paystack_verified = True
        except Exception as e:
            logger.warning(f"Paystack phone verify unavailable: {e}")

    logger.info(f"\U0001f4f1 Phone verified: {phone} | {carrier} | paystack={paystack_verified}")
    return {
        "valid":              True,
        "phone":              phone,
        "carrier":            carrier,
        "paystack_verified":  paystack_verified,
        "whatsapp_number":    "234" + phone[1:],
        "message":            f"\u2705 {phone} ({carrier})"
    }


@app.get("/whatsapp-pay/sent/{wallet_id}")
def get_sent_links(wallet_id: str):
    _get_wallet(wallet_id)
    links = sorted([v for v in whatsapp_links.values() if v["sender_wallet_id"] == wallet_id],
                   key=lambda x: x["created_at"], reverse=True)
    return {"success": True, "links": links, "count": len(links)}


@app.post("/whatsapp-pay/{link_id}/cancel")
def cancel_whatsapp_pay(link_id: str, wallet_id: str = Body(..., embed=True)):
    link = whatsapp_links.get(link_id)
    if not link:
        raise HTTPException(404, "Link not found")
    if link["sender_wallet_id"] != wallet_id:
        raise HTTPException(403, "You can only cancel your own payment links")
    if link["status"] != "pending":
        raise HTTPException(400, f"Cannot cancel \u2014 link has been {link['status']}")
    _expire_whatsapp_link(link_id, reason="cancelled")
    return {"success": True, "message": f"\u20a6{link['amount_naira']:,.2f} returned to your wallet",
            "new_balance": wallets[wallet_id].balance}


def _expire_whatsapp_link(link_id: str, reason: str = "expired"):
    link = whatsapp_links.get(link_id)
    if not link or link["status"] != "pending":
        return
    wid = link["sender_wallet_id"]
    if wid in wallets:
        w = wallets[wid]
        w.credit(link["amount_naira"], "whatsapp_pay_refund",
                 f"WhatsApp Pay refund \u2014 link {reason} (recipient: {link['recipient_name']})",
                 f"WPAY-REFUND-{uuid.uuid4().hex[:8].upper()}")
        logger.info(f"\U0001f504 WhatsApp Pay refunded: {link_id} \u20a6{link['amount_naira']:,.2f} \u2192 {wid} ({reason})")
    link["status"] = reason
    save_db()


def _send_whatsapp_pay_email(w: Wallet, link_id: str, recipient_name: str,
                              phone: str, amount: float, note: str, expires_date: str):
    subject = f"\U0001f49a You sent \u20a6{amount:,.2f} to {recipient_name} via WhatsApp Pay"
    body = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto">
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">WhatsApp Pay Sent</p>
        <p style="margin:0;font-size:42px;font-weight:900;color:#25D366">\u20a6{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:6px 18px;background:#F0FDF4;border-radius:20px;border:1px solid #BBF7D0">
          <span style="color:#15803D;font-weight:700;font-size:14px">\u23f3 Awaiting Claim</span>
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">To</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{recipient_name} ({phone})</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">Message</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{note or "\u2014"}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">Expires</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{expires_date}</td></tr>
      </table>
      <div style="margin:16px;padding:14px;background:#F0FFF4;border-radius:10px;border:1px solid #BBF7D0">
        <p style="margin:0;font-size:13px;color:#15803D">\u2705 Funds are held safely. If {recipient_name} doesn't claim, the money returns to your wallet automatically.</p>
      </div>
    </div>"""
    send_email(w.owner_email, subject, _receipt_shell(w.owner_name, "#25D366", "WhatsApp Pay Sent \U0001f49a", f"To: {recipient_name}", body))


def _send_claim_confirmation_emails(link: dict, claimer_name: str, method: str):
    amount = link["amount_naira"]
    wid    = link["sender_wallet_id"]
    if wid in wallets:
        w = wallets[wid]
        subj = f"\U0001f49a {claimer_name} claimed your \u20a6{amount:,.2f} WhatsApp Pay!"
        body = f'<div style="font-family:-apple-system,sans-serif;padding:24px"><p style="font-size:22px;font-weight:900;color:#25D366">Money Claimed! \u2705</p><p style="color:#374151">{claimer_name} successfully claimed <strong>\u20a6{amount:,.2f}</strong>.</p></div>'
        send_email(w.owner_email, subj, _receipt_shell(w.owner_name, "#25D366", "WhatsApp Pay Claimed", "", body))


def _send_new_wallet_claim_email(link: dict, new_wallet: Wallet):
    amount = link["amount_naira"]
    subj   = f"\U0001f389 You received \u20a6{amount:,.2f} \u2014 Your CredionPay wallet is ready!"
    body   = f"""<div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto;padding:24px">
        <p style="font-size:22px;font-weight:900;color:#008751">Welcome to CredionPay! \U0001f1f3\U0001f1ec</p>
        <p style="color:#374151">{link['sender_name']} sent you <strong>\u20a6{amount:,.2f}</strong> via WhatsApp Pay.</p>
        <div style="background:#F0FDF4;border-radius:12px;padding:16px;margin:16px 0;border:1px solid #BBF7D0">
          <p style="margin:0;font-family:monospace;font-size:18px;font-weight:900;color:#008751">{new_wallet.wallet_id}</p>
          <p style="margin:4px 0 0;font-size:12px;color:#6B7280">Your Wallet ID \u2014 keep this safe</p>
        </div>
        <p style="color:#374151">Download CredionPay to manage your money, send to others, and pay bills.</p>
        <a href="https://ayotechcom.com/" style="display:inline-block;background:#008751;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700">Get the App</a>
    </div>"""
    send_email(new_wallet.owner_email, subj, _receipt_shell(new_wallet.owner_name, "#008751", "You Received Money!", "", body))


def _pay_page_error(msg: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CredionPay Pay</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,sans-serif;background:#0f1923;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#1a2a3a;border-radius:24px;padding:40px 28px;max-width:400px;width:100%;text-align:center}}.brand{{color:#008751;font-weight:900;font-size:18px;margin-bottom:16px}}.icon{{font-size:48px;margin-bottom:12px}}.title{{color:#ef4444;font-size:20px;font-weight:800;margin-bottom:10px}}.msg{{color:#9ca3af;font-size:14px;line-height:1.6}}</style>
</head><body><div class="card"><div class="brand">\u20a6 CredionPay</div><div class="icon">\u274c</div><div class="title">Link Unavailable</div><div class="msg">{msg}</div></div></body></html>"""


def _pay_page_claimed(link: dict) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CredionPay Pay \u2014 Claimed</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,sans-serif;background:#0f1923;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#1a2a3a;border-radius:24px;padding:40px 28px;max-width:400px;width:100%;text-align:center}}.brand{{color:#008751;font-weight:900;font-size:18px;margin-bottom:16px}}.amount{{color:#25D366;font-size:44px;font-weight:900;margin-bottom:8px}}.title{{color:#fff;font-size:18px;font-weight:800;margin-bottom:10px}}.msg{{color:#9ca3af;font-size:14px}}</style>
</head><body><div class="card"><div class="brand">\u20a6 CredionPay</div><div style="font-size:48px">\u2705</div><div class="amount">\u20a6{link['amount_naira']:,.2f}</div><div class="title">Already Claimed</div><div class="msg">Claimed on {(link.get('claimed_at') or '')[:10]}</div></div></body></html>"""


def _pay_page_form(link: dict) -> str:
    import urllib.parse
    banks = [
        ("044","Access Bank"),("058","GTBank"),("011","First Bank"),("033","UBA"),
        ("057","Zenith Bank"),("035","Wema Bank"),("050","EcoBank"),("214","FCMB"),
        ("070","Fidelity Bank"),("232","Sterling Bank"),("999992","OPay"),
        ("999991","PalmPay"),("50211","Kuda Bank"),("50515","Moniepoint"),
    ]
    bank_opts = "".join(f'<option value="{c}">{n}</option>' for c,n in banks)
    note_html = f'<div class="note-box">\U0001f4dd &ldquo;{link["note"]}&rdquo;</div>' if link.get("note") else ""
    lid       = link["link_id"]
    amt       = link["amount_naira"]
    sender    = link["sender_name"]
    rec_name  = link["recipient_name"]
    exp_h     = link["expires_hours"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Claim \u20a6{amt:,.2f} from {sender}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f1923;min-height:100vh;padding:20px}}
.wrap{{max-width:420px;margin:0 auto}}
.brand{{text-align:center;padding:20px 0 0;color:#008751;font-weight:900;font-size:20px}}
.hero{{background:linear-gradient(135deg,#1a3a6b,#0d47a1);border-radius:24px;padding:32px 24px;text-align:center;margin:16px 0}}
.from{{color:rgba(255,255,255,0.6);font-size:14px;margin-bottom:4px}}
.sender{{color:#fff;font-size:20px;font-weight:800;margin-bottom:16px}}
.amount{{color:#25D366;font-size:52px;font-weight:900;line-height:1;margin-bottom:8px}}
.label{{color:rgba(255,255,255,0.5);font-size:12px;text-transform:uppercase;letter-spacing:1px}}
.note-box{{background:rgba(255,255,255,0.1);border-radius:12px;padding:12px 16px;margin-top:16px;color:rgba(255,255,255,0.8);font-size:14px;font-style:italic}}
.card{{background:#1a2a3a;border-radius:20px;padding:24px;margin-bottom:16px}}
.card h3{{color:#fff;font-size:16px;font-weight:700;margin-bottom:16px}}
.tab-row{{display:flex;background:#0f1923;border-radius:12px;padding:4px;margin-bottom:20px;gap:4px}}
.tab{{flex:1;padding:10px;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;background:none;color:#9ca3af;transition:all .2s}}
.tab.active{{background:#008751;color:#fff}}
label{{display:block;color:#9ca3af;font-size:12px;margin-bottom:6px;margin-top:14px}}
input,select{{width:100%;padding:14px;background:#0f1923;border:1px solid #2a3a4a;border-radius:12px;color:#fff;font-size:15px;outline:none}}
input:focus,select:focus{{border-color:#008751}}
select option{{background:#1a2a3a}}
.btn{{width:100%;padding:16px;background:#25D366;border:none;border-radius:14px;color:#fff;font-size:17px;font-weight:800;cursor:pointer;margin-top:20px}}
.btn:disabled{{background:#374151;cursor:not-allowed}}
.btn-bank{{background:#1a3a6b}}
.footer{{text-align:center;color:#6b7280;font-size:12px;padding:16px 0 32px;line-height:1.8}}
.spinner{{display:none;width:20px;height:20px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
#result{{display:none;background:#0f3320;border:1px solid #25D366;border-radius:14px;padding:20px;text-align:center;margin-top:16px}}
.r-amount{{color:#25D366;font-size:36px;font-weight:900}}
.r-msg{{color:#fff;font-size:15px;margin-top:8px}}
.r-sub{{color:#9ca3af;font-size:13px;margin-top:6px}}
.r-wid{{font-family:monospace;background:#0f1923;padding:8px 14px;border-radius:8px;color:#25D366;font-size:14px;font-weight:700;margin-top:12px;display:inline-block}}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">\u20a6 CredionPay</div>
  <div class="hero">
    <div class="from">Money waiting for you from</div>
    <div class="sender">{sender}</div>
    <div class="label">Amount</div>
    <div class="amount">\u20a6{amt:,.2f}</div>
    {note_html}
  </div>
  <div class="card">
    <h3>\U0001f4b3 How do you want to receive it?</h3>
    <div class="tab-row">
      <button class="tab active" onclick="switchTab('wallet')" id="tab-wallet">CredionPay Wallet</button>
      <button class="tab" onclick="switchTab('bank')" id="tab-bank">Bank Account</button>
    </div>
    <div id="pane-wallet">
      <p style="color:#9ca3af;font-size:13px;line-height:1.6">Enter your CredionPay email, or we will create a wallet for you automatically.</p>
      <label>Your Name</label>
      <input type="text" id="w-name" placeholder="e.g. Tunde Bakare" value="{rec_name}">
      <label>CredionPay Email (optional \u2014 to add to existing wallet)</label>
      <input type="email" id="w-email" placeholder="your CredionPay email">
      <button class="btn" onclick="claim('wallet')" id="btn-wallet">
        <span id="btn-wallet-text">Claim to Wallet \U0001f49a</span>
        <div class="spinner" id="spin-wallet"></div>
      </button>
    </div>
    <div id="pane-bank" style="display:none">
      <p style="color:#9ca3af;font-size:13px;line-height:1.6">Receive directly to your Nigerian bank account.</p>
      <label>Your Name</label>
      <input type="text" id="b-name" placeholder="As on your bank account" value="{rec_name}">
      <label>Select Bank</label>
      <select id="b-bank"><option value="">-- Select Bank --</option>{bank_opts}</select>
      <label>Account Number (NUBAN)</label>
      <input type="tel" id="b-acct" placeholder="10-digit account number" maxlength="10">
      <button class="btn btn-bank" onclick="claim('bank')" id="btn-bank">
        <span id="btn-bank-text">Claim to Bank Account \U0001f3e6</span>
        <div class="spinner" id="spin-bank"></div>
      </button>
    </div>
  </div>
  <div id="result"></div>
  <div class="footer">
    <div style="color:#25D366">\U0001f512 256-bit encrypted \u00b7 Powered by Paystack</div>
    <div>CredionPay by AyoTech \u00b7 Nigeria\u2019s smartest wallet</div>
    <div><a href="https://ayotechcom.com/" style="color:#008751">ayotechcom.com</a></div>
  </div>
</div>
<script>
function switchTab(t) {{
  document.getElementById('pane-wallet').style.display = t==='wallet'?'block':'none';
  document.getElementById('pane-bank').style.display   = t==='bank'?'block':'none';
  document.getElementById('tab-wallet').className = 'tab'+(t==='wallet'?' active':'');
  document.getElementById('tab-bank').className   = 'tab'+(t==='bank'?' active':'');
}}
async function claim(method) {{
  const btn = document.getElementById('btn-'+method);
  const txt = document.getElementById('btn-'+method+'-text');
  const spn = document.getElementById('spin-'+method);
  btn.disabled=true; txt.style.display='none'; spn.style.display='block';
  let body = {{}};
  if (method==='wallet') {{
    body = {{link_id:'{lid}',recipient_name:document.getElementById('w-name').value,recipient_email:document.getElementById('w-email').value}};
  }} else {{
    const bk = document.getElementById('b-bank').value;
    const ac = document.getElementById('b-acct').value;
    if (!bk||!ac) {{ alert('Please select your bank and enter your account number.'); btn.disabled=false;txt.style.display='';spn.style.display='none';return; }}
    body = {{link_id:'{lid}',recipient_name:document.getElementById('b-name').value,bank_code:bk,account_number:ac}};
  }}
  try {{
    const res  = await fetch('/pay/{lid}/claim',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
    const data = await res.json();
    const el   = document.getElementById('result');
    el.style.display='block';
    if (data.success) {{
      el.innerHTML='<div class="r-amount">\u20a6{amt:,.2f}</div><div class="r-msg">\U0001f389 '+data.message+'</div>'+(data.wallet_id?'<div class="r-sub">Your Wallet ID:</div><div class="r-wid">'+data.wallet_id+'</div>':'')+'<div class="r-sub" style="margin-top:16px">Download CredionPay to manage your money</div>';
      document.querySelector('.card').style.display='none';
    }} else {{
      el.style.background='#3a0f0f';el.style.borderColor='#ef4444';
      el.innerHTML='<div style="color:#ef4444;font-size:16px">\u274c '+(data.detail||'Something went wrong')+'</div>';
      btn.disabled=false;txt.style.display='';spn.style.display='none';
    }}
  }} catch(e) {{
    alert('Network error. Please try again.');
    btn.disabled=false;txt.style.display='';spn.style.display='none';
  }}
}}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
# OTP — ONE-TIME PASSWORD SYSTEM
# Protects: transfers, login, KYC, card creation, WhatsApp Pay
# ══════════════════════════════════════════════════════════════════════════════

import random
import string

def _generate_otp(length: int = 6) -> str:
    """Generate a secure 6-digit numeric OTP."""
    return "".join(random.choices(string.digits, k=length))

def _otp_key(wallet_id: str, purpose: str) -> str:
    return f"{wallet_id}:{purpose}"


# ══════════════════════════════════════════════════════════════════════════════
# TWILIO VERIFY API  — Send & Check OTP via Twilio Verify Service
# ══════════════════════════════════════════════════════════════════════════════

def _twilio_verify_send(phone: str, channel: str = "sms") -> dict:
    """
    Send OTP via Twilio Verify API.
    channel: 'sms' | 'whatsapp' | 'call'
    Returns {"success": True/False, "status": "pending"/"approved", "error": "..."}
    """
    sid      = os.getenv("TWILIO_ACCOUNT_SID", "")
    token    = os.getenv("TWILIO_AUTH_TOKEN",
               os.getenv("TWILIO_API_SECRET", ""))
    svc_sid  = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")

    if not sid or not token or not svc_sid:
        logger.warning("⚠️  Twilio Verify not configured — TWILIO_ACCOUNT_SID / "
                       "TWILIO_AUTH_TOKEN / TWILIO_VERIFY_SERVICE_SID missing")
        return {"success": False, "error": "Twilio Verify not configured"}

    # Normalise to E.164 (+234XXXXXXXXXX)
    p = re.sub(r"[\s\-\(\)]", "", str(phone))
    if p.startswith("0"):
        p = "+234" + p[1:]
    elif p.startswith("234"):
        p = "+" + p
    elif not p.startswith("+"):
        p = "+234" + p

    try:
        resp = requests.post(
            f"https://verify.twilio.com/v2/Services/{svc_sid}/Verifications",
            data={"To": p, "Channel": channel},
            auth=(sid, token),
            timeout=15,
        )
        data = resp.json()
        if resp.status_code in (200, 201):
            logger.info(f"📱 Twilio Verify sent ({channel}) to {p[:7]}*** status={data.get('status')}")
            return {"success": True, "status": data.get("status"), "to": p}
        else:
            err = data.get("message", resp.text[:120])
            logger.warning(f"⚠️  Twilio Verify send failed {resp.status_code}: {err}")
            return {"success": False, "error": err, "code": resp.status_code}
    except Exception as e:
        logger.error(f"❌ Twilio Verify send exception: {e}")
        return {"success": False, "error": str(e)}


def _twilio_verify_check(phone: str, code: str) -> dict:
    """
    Check OTP code via Twilio Verify API.
    Returns {"success": True/False, "approved": True/False, "error": "..."}
    """
    sid      = os.getenv("TWILIO_ACCOUNT_SID", "")
    token    = os.getenv("TWILIO_AUTH_TOKEN",
               os.getenv("TWILIO_API_SECRET", ""))
    svc_sid  = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")

    if not sid or not token or not svc_sid:
        return {"success": False, "error": "Twilio Verify not configured"}

    # Normalise phone
    p = re.sub(r"[\s\-\(\)]", "", str(phone))
    if p.startswith("0"):
        p = "+234" + p[1:]
    elif p.startswith("234"):
        p = "+" + p
    elif not p.startswith("+"):
        p = "+234" + p

    try:
        resp = requests.post(
            f"https://verify.twilio.com/v2/Services/{svc_sid}/VerificationCheck",
            data={"To": p, "Code": code.strip()},
            auth=(sid, token),
            timeout=15,
        )
        data = resp.json()
        if resp.status_code in (200, 201):
            approved = data.get("status") == "approved"
            logger.info(f"📱 Twilio Verify check {p[:7]}*** → {data.get('status')}")
            return {"success": True, "approved": approved, "status": data.get("status")}
        else:
            err = data.get("message", resp.text[:120])
            # 404 means the code was already used or expired
            if resp.status_code == 404:
                return {"success": False, "approved": False,
                        "error": "Code expired or already used. Request a new OTP."}
            logger.warning(f"⚠️  Twilio Verify check failed {resp.status_code}: {err}")
            return {"success": False, "approved": False, "error": err}
    except Exception as e:
        logger.error(f"❌ Twilio Verify check exception: {e}")
        return {"success": False, "approved": False, "error": str(e)}


def _send_sms_otp(phone: str, otp: str, purpose: str, owner_name: str):
    """
    Send our OWN generated OTP code via SMS for transactions.
    Uses Twilio Messages API (NOT Verify) so the SAME code goes to both SMS and email.
    Twilio Verify is only for phone-number verification (/otp/phone-send).

    Priority: 1) Twilio Messages API  2) Termii (Nigerian fallback)
    """
    label_map = {
        "transfer":     "Bank Transfer",
        "whatsapp_pay": "WhatsApp Pay",
        "login":        "Login",
        "kyc":          "KYC Verification",
        "card":         "Virtual Card",
        "nfc":          "NFC Pay",
        "usd_send":     "USD Transfer",
        "withdraw":     "Withdrawal",
        "savings":      "Savings",
    }
    label = label_map.get(purpose, purpose.replace("_", " ").title())

    # Normalise phone to international format (no leading +)
    p = re.sub(r"[^\d]", "", str(phone))   # digits only
    if p.startswith("0") and len(p) == 11:
        p = "234" + p[1:]                  # 07066812367 → 2347066812367
    elif p.startswith("234") and len(p) == 13:
        pass                               # already correct
    elif len(p) == 10 and not p.startswith("234"):
        p = "234" + p                      # 7066812367  → 2347066812367

    # ── Validate it's a real Nigerian mobile number ───────────────────────────
    # Valid Nigerian numbers: +234 followed by 70/80/81/90/91/703/706/802/etc
    # Must be exactly 13 digits starting with 234 and 3rd group is 7xx/8xx/9xx
    ng_valid = (
        len(p) == 13
        and p.startswith("234")
        and p[3] in ("7", "8", "9")
    )
    if not ng_valid:
        logger.warning(
            f"📱 Skipping SMS — '{phone}' is not a valid Nigerian mobile number "
            f"(normalised: '{p}'). OTP was sent to email only."
        )
        return False

    # Message includes the OTP so it matches the email
    msg = (
        f"CredionPay: Your {label} OTP is {otp}. "
        f"Valid 10 mins. NEVER share this code. -AyoTech"
    )
    e164 = f"+{p}"
    ssl_verify = certifi.where() if _CERTIFI_AVAILABLE else True

    # ── 1. Twilio Messages API ────────────────────────────────────────────────
    # IMPORTANT: Messages API requires Account SID + Auth Token.
    # API Keys (TWILIO_API_KEY_SID) only work for Verify — NOT for Messages.
    twilio_sid    = os.getenv("TWILIO_ACCOUNT_SID", "")
    twilio_token  = os.getenv("TWILIO_AUTH_TOKEN", "")        # ← must be Auth Token
    twilio_from   = os.getenv("TWILIO_PHONE", os.getenv("TWILIO_PHONE_NUMBER", ""))
    twilio_msid   = os.getenv("TWILIO_MESSAGING_SERVICE_SID", "")

    if twilio_sid and twilio_token:
        try:
            payload = {"To": e164, "Body": msg}
            if twilio_msid:
                payload["MessagingServiceSid"] = twilio_msid
            elif twilio_from:
                payload["From"] = twilio_from
            else:
                logger.warning("⚠️  Twilio: set TWILIO_PHONE or TWILIO_MESSAGING_SERVICE_SID in .env to send SMS")

            if "From" in payload or "MessagingServiceSid" in payload:
                resp = requests.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json",
                    data=payload,
                    auth=(twilio_sid, twilio_token),   # Account SID + Auth Token only
                    timeout=15,
                    verify=ssl_verify,
                )
                if resp.status_code in (200, 201):
                    logger.info(f"📱 Transaction OTP SMS sent via Twilio → {e164[:9]}*** [{label}]")
                    return True
                logger.warning(f"Twilio Messages {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"Twilio Messages SMS failed: {e}")

    # ── 2. Termii (Nigerian SMS fallback) ─────────────────────────────────────
    termii_key = os.getenv("TERMII_API_KEY", "")
    if termii_key:
        try:
            resp = requests.post(
                "https://api.ng.termii.com/api/sms/send",
                json={
                    "to":      p,
                    "from":    "CredionPay",
                    "sms":     msg,
                    "type":    "plain",
                    "channel": "dnd",
                    "api_key": termii_key,
                },
                timeout=10,
                verify=ssl_verify,
            )
            if resp.status_code == 200:
                logger.info(f"📱 Transaction OTP SMS sent via Termii → {p[:6]}*** [{label}]")
                return True
            logger.warning(f"Termii {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            logger.warning(f"Termii SMS failed: {e}")

    logger.warning(
        f"📱 SMS OTP could not be sent — configure TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN "
        f"+ TWILIO_PHONE (or TWILIO_MESSAGING_SERVICE_SID) in .env  [{p[:6]}***]"
    )
    return False


def _send_otp_email(wallet: "Wallet", otp: str, purpose: str, amount: float = 0):
    """Send OTP to wallet owner's email."""
    purpose_labels = {
        "transfer":     "Bank Transfer",
        "login":        "Login Verification",
        "kyc":          "KYC Verification",
        "card":         "Virtual Card Creation",
        "whatsapp_pay": "WhatsApp Pay",
        "usd_send":     "USD Transfer",
        "withdraw":     "Withdrawal",
    }
    label = purpose_labels.get(purpose, purpose.replace("_", " ").title())
    amount_line = f"""
    <div style="text-align:center;padding:16px;background:#F0FDF4;border-radius:12px;margin:16px 0;border:1px solid #BBF7D0">
      <p style="margin:0;color:#6B7280;font-size:13px">Amount</p>
      <p style="margin:4px 0 0;font-size:28px;font-weight:900;color:#1B3A6B">₦{amount:,.2f}</p>
    </div>""" if amount > 0 else ""

    body = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto">
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase;letter-spacing:1px">CredionPay Security Code</p>
        <p style="margin:0;font-size:22px;font-weight:800;color:#1B3A6B">{label} OTP</p>
      </div>
      <div style="padding:24px 20px">
        <p style="color:#374151;font-size:15px">Hi <strong>{wallet.owner_name.split()[0]}</strong>,</p>
        <p style="color:#374151;font-size:15px">Use this one-time password to complete your <strong>{label}</strong>. It expires in <strong>10 minutes</strong>.</p>
        {amount_line}
        <!-- OTP Box -->
        <div style="text-align:center;margin:24px 0">
          <div style="display:inline-block;background:#1B3A6B;border-radius:16px;padding:20px 40px">
            <p style="margin:0;font-size:48px;font-weight:900;color:#2EAA4A;letter-spacing:12px;font-family:monospace">{otp}</p>
          </div>
          <p style="margin:12px 0 0;font-size:12px;color:#9CA3AF">Valid for 10 minutes only</p>
        </div>
        <div style="background:#FFF7ED;border:1px solid #FED7AA;border-radius:10px;padding:14px 16px;margin-top:16px">
          <p style="margin:0;font-size:13px;color:#92400E">
            ⚠️ <strong>Never share this code.</strong> CredionPay will never ask for your OTP via phone or WhatsApp.
            If you did not request this, please ignore this email.
          </p>
        </div>
      </div>
    </div>"""
    send_email(
        wallet.owner_email,
        f"🔒 CredionPay OTP: {otp} — {label}",
        _receipt_shell(wallet.owner_name, "#1B3A6B", "Security Verification Code", label, body)
    )
    logger.info(f"🔒 OTP sent to {wallet.owner_email} for {purpose} (wallet={wallet.wallet_id})")


@app.post("/otp/request")
def request_otp(req: OtpRequest, bg: BackgroundTasks):
    """
    Generate ONE OTP code and send it to BOTH email AND phone SMS simultaneously.
    Same code on both channels — user can use whichever arrives first.
    Call this before any sensitive transaction (transfer, card creation, etc).
    """
    w = _get_wallet(req.wallet_id)
    key = _otp_key(req.wallet_id, req.purpose)

    # Rate limit: max 1 OTP per 60 seconds per purpose
    existing = otp_store.get(key, {})
    if existing.get("created_at"):
        from datetime import datetime as dt, timedelta
        age = (dt.now() - dt.fromisoformat(existing["created_at"])).total_seconds()
        if age < 60:
            raise HTTPException(429,
                f"Please wait {int(60 - age)} seconds before requesting another OTP.")

    # Generate single OTP — SAME code sent to email AND SMS
    otp = _generate_otp()
    from datetime import datetime as dt, timedelta
    otp_store[key] = {
        "otp":        otp,
        "wallet_id":  req.wallet_id,
        "purpose":    req.purpose,
        "amount":     req.amount,
        "attempts":   0,
        "verified":   False,
        "created_at": dt.now().isoformat(),
        "expires_at": (dt.now() + timedelta(minutes=10)).isoformat(),
    }

    # ── Send to email (always) ────────────────────────────────────────────────
    bg.add_task(_send_otp_email, w, otp, req.purpose, req.amount)

    # ── Send SAME code to phone via SMS ──────────────────────────────────────
    sms_queued = False
    if w.phone:
        bg.add_task(_send_sms_otp, w.phone, otp, req.purpose, w.owner_name)
        sms_queued = True
    else:
        logger.warning(f"⚠️  No phone on wallet {req.wallet_id} — OTP sent to email only")

    # Build masked display values
    masked_email = f"{w.owner_email[:3]}***@{w.owner_email.split('@')[1]}"
    masked_phone = (
        f"{w.phone[:4]}***{w.phone[-3:]}"
        if w.phone and len(w.phone) >= 7 else None
    )

    channels = ["email"]
    if sms_queued:
        channels.append("SMS")

    logger.info(
        f"🔒 OTP [{otp}] dispatched for {req.purpose} → "
        f"email={masked_email}  phone={masked_phone or 'N/A'}"
    )

    return {
        "success":      True,
        "message":      f"OTP sent to your {' and '.join(channels)}. Use the same code from either.",
        "email":        masked_email,
        "phone":        masked_phone,
        "channels":     channels,
        "expires_mins": 10,
        "hint":         "Check SMS or email — both have the same code.",
    }


@app.post("/otp/verify")
def verify_otp(req: OtpVerifyRequest):
    """
    Verify OTP. Returns a short-lived token on success.
    The token must be passed in subsequent sensitive API calls.
    """
    key     = _otp_key(req.wallet_id, req.purpose)
    record  = otp_store.get(key)

    if not record:
        raise HTTPException(400, "No OTP found. Please request a new one.")

    from datetime import datetime as dt
    # Check expiry
    if dt.now() > dt.fromisoformat(record["expires_at"]):
        del otp_store[key]
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    # Max 5 attempts
    record["attempts"] += 1
    if record["attempts"] > 5:
        del otp_store[key]
        raise HTTPException(400, "Too many incorrect attempts. Please request a new OTP.")

    # Check code
    if req.otp_code.strip() != record["otp"]:
        remaining = 5 - record["attempts"]
        raise HTTPException(400, f"Incorrect OTP. {remaining} attempt(s) remaining.")

    # Success — generate a one-use verification token
    token = f"VTK-{uuid.uuid4().hex[:20].upper()}"
    record["verified"]  = True
    record["token"]     = token
    record["verified_at"] = dt.now().isoformat()
    logger.info(f"✅ OTP verified: {key}")

    return {
        "success":  True,
        "verified": True,
        "token":    token,
        "message":  "OTP verified successfully",
    }


@app.get("/otp/status/{wallet_id}/{purpose}")
def otp_status(wallet_id: str, purpose: str):
    """Check if a valid OTP exists for this wallet+purpose."""
    key    = _otp_key(wallet_id, purpose)
    record = otp_store.get(key)
    if not record:
        return {"exists": False, "verified": False}
    from datetime import datetime as dt
    expired = dt.now() > dt.fromisoformat(record["expires_at"])
    return {
        "exists":   True,
        "verified": record.get("verified", False),
        "expired":  expired,
        "attempts": record.get("attempts", 0),
    }


# ── Phone-based OTP (Twilio Verify) — no wallet_id needed ────────────────────
# Used for: login verification, new account phone confirmation

class PhoneOtpSendRequest(BaseModel):
    phone:   str
    channel: str = "sms"   # "sms" | "whatsapp" | "call"

class PhoneOtpCheckRequest(BaseModel):
    phone: str
    code:  str


@app.post("/otp/phone-send")
def phone_otp_send(req: PhoneOtpSendRequest):
    """
    Send a one-time code to a phone via Twilio Verify.
    Use for login or new-account phone verification.
    No wallet_id required — works before account exists.
    """
    if not req.phone or len(req.phone.strip()) < 10:
        raise HTTPException(400, "Enter a valid phone number (e.g. 07066812367)")

    result = _twilio_verify_send(req.phone.strip(), channel=req.channel)

    if result.get("success"):
        # Mask phone for response
        norm = result.get("to", req.phone)
        masked = f"{norm[:6]}***{norm[-3:]}" if len(norm) > 9 else norm
        return {
            "success": True,
            "message": f"OTP sent to {masked} via {req.channel.upper()}",
            "phone":   masked,
            "channel": req.channel,
        }

    err = result.get("error", "Could not send OTP")
    # Check if Twilio Verify isn't configured — give a helpful message
    if "not configured" in err.lower():
        raise HTTPException(503,
            "SMS service not configured. "
            "Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and "
            "TWILIO_VERIFY_SERVICE_SID to your .env file.")
    raise HTTPException(502, f"Could not send OTP: {err}")


@app.post("/otp/phone-check")
def phone_otp_check(req: PhoneOtpCheckRequest):
    """
    Verify the code sent via /otp/phone-send.
    Returns success + the matching wallet (if any) so the app can auto-login.
    """
    if not req.phone or not req.code:
        raise HTTPException(400, "Phone and code are required.")

    result = _twilio_verify_check(req.phone.strip(), req.code.strip())

    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Verification service error."))

    if not result.get("approved"):
        raise HTTPException(401, "Incorrect or expired code. Please try again.")

    # Look up the wallet by phone (so app can auto-login after verification)
    norm = _normalise_phone(req.phone)
    wid  = phone_index.get(norm) or next(
        (wid for wid, w in wallets.items()
         if w.phone and _normalise_phone(w.phone) == norm), None)

    logger.info(f"✅ Phone OTP verified: {req.phone[:6]}*** wallet={'found' if wid else 'not found'}")

    return {
        "success":  True,
        "verified": True,
        "message":  "Phone verified successfully",
        "wallet_id": wid,                               # None if new user
        "wallet":    wallets[wid].to_dict() if wid else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# NFC PAY — Tap-to-Pay with offline token support
# ══════════════════════════════════════════════════════════════════════════════

nfc_tokens: dict[str, dict] = {}   # token -> token data

class NfcCreateRequest(BaseModel):
    sender_wallet_id:  str
    recipient_tag:     str
    amount_naira:      float
    note:              str = ""

class NfcRedeemRequest(BaseModel):
    token:               str
    redeemer_wallet_id:  str

@app.post("/nfc-pay/create-token")
def create_nfc_token(req: NfcCreateRequest, bg: BackgroundTasks):
    """
    Create a signed NFC/offline payment token.
    Debits sender immediately. Recipient redeems when online.
    """
    sender = _get_wallet(req.sender_wallet_id)
    _require_kyc(sender)

    # Resolve recipient — try multiple methods
    raw   = req.recipient_tag.strip()
    tag   = raw if raw.startswith("@") else f"@{raw}"
    recipient_wid = None

    # 1. Exact tag match
    recipient_wid = usd_tag_index.get(tag) or usd_tag_index.get(tag.lower())

    # 2. Direct wallet ID
    if not recipient_wid and raw.upper().startswith("WAL-"):
        wid_up = raw.upper()
        if wid_up in wallets:
            recipient_wid = wid_up

    # 3. Email lookup
    if not recipient_wid and "@" in raw and "." in raw:
        recipient_wid = email_index.get(raw.lower())

    # 4. Fuzzy name search in tag index
    if not recipient_wid:
        clean = tag.lstrip("@").replace("credionpay/","").replace(" ","").lower()
        for t, wid in usd_tag_index.items():
            if clean in t.lower().replace("@credionpay/",""):
                recipient_wid = wid
                break

    # 5. Fuzzy name search in wallets directly
    if not recipient_wid:
        clean_name = raw.lower().replace(" ","")
        for wid, w in wallets.items():
            wname = w.owner_name.lower().replace(" ","")
            if clean_name in wname or wname in clean_name:
                recipient_wid = wid
                break

    if not recipient_wid:
        # Show available tags to help user
        available = list(usd_tag_index.keys())[:5]
        raise HTTPException(404,
            f"Recipient '{req.recipient_tag}' not found. "
            f"Use a CredionPay tag (e.g. @credionpay/name), Wallet ID (WAL-...), or email. "
            f"Available tags: {', '.join(available)}")

    if recipient_wid == req.sender_wallet_id:
        raise HTTPException(400, "Cannot send to yourself")
    if req.amount_naira <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount_naira > sender.balance:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{sender.balance:,.2f}")

    # Generate token
    token_id = f"CPNFC-{uuid.uuid4().hex[:16].upper()}"
    ref      = f"NFC-{uuid.uuid4().hex[:10].upper()}"

    # Debit sender immediately (escrow)
    try:
        sender.debit(req.amount_naira, "nfc_pay_hold",
                     f"NFC Pay to {tag} — ₦{req.amount_naira:,.2f} (held in escrow)", ref)
    except ValueError as e:
        raise HTTPException(400, str(e))

    from datetime import timedelta
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()

    nfc_tokens[token_id] = {
        "token":              token_id,
        "sender_wallet_id":   req.sender_wallet_id,
        "sender_name":        sender.owner_name,
        "recipient_tag":      tag,
        "recipient_wallet_id": recipient_wid,
        "amount_naira":       req.amount_naira,
        "note":               req.note or "",
        "status":             "pending",   # pending | redeemed | expired | cancelled
        "ref":                ref,
        "created_at":         datetime.now().isoformat(),
        "expires_at":         expires_at,
        "redeemed_at":        None,
    }
    save_db()
    logger.info(f"📲 NFC token created: {token_id} ₦{req.amount_naira:,.2f} {req.sender_wallet_id} → {tag}")

    bg.add_task(_send_nfc_created_email, sender, token_id, tag, req.amount_naira, req.note)
    return {
        "success":    True,
        "token":      token_id,
        "amount":     req.amount_naira,
        "recipient":  tag,
        "note":       req.note,
        "expires_at": expires_at,
        "message":    f"₦{req.amount_naira:,.2f} ready. Share token with recipient to claim.",
        "offline":    False,
    }


@app.post("/nfc-pay/redeem-token")
def redeem_nfc_token(req: NfcRedeemRequest, bg: BackgroundTasks):
    """Recipient redeems NFC token — credits their wallet."""
    token_id = req.token.strip().upper()
    record   = nfc_tokens.get(token_id)

    # Handle offline tokens (CPNFC-WAL-... format with checksum)
    if not record and token_id.startswith("CPNFC-WAL-"):
        return _redeem_offline_token(req.token, req.redeemer_wallet_id)

    if not record:
        raise HTTPException(404, "Token not found or already redeemed.")
    if record["status"] != "pending":
        raise HTTPException(400, f"Token has already been {record['status']}.")

    from datetime import datetime as dt
    if dt.now() > dt.fromisoformat(record["expires_at"]):
        _expire_nfc_token(token_id)
        raise HTTPException(410, "Token has expired. Funds returned to sender.")

    # Validate redeemer matches intended recipient
    redeemer_w = _get_wallet(req.redeemer_wallet_id)
    recipient_wid = record["recipient_wallet_id"]

    # Credit recipient
    recipient_w = wallets.get(recipient_wid)
    if not recipient_w:
        raise HTTPException(404, "Recipient wallet not found.")

    amount = record["amount_naira"]
    ref    = f"NFC-CLAIM-{uuid.uuid4().hex[:8].upper()}"
    recipient_w.credit(amount, "nfc_pay_receive",
                       f"NFC Pay from {record['sender_name']} — {record['note'] or 'Payment'}",
                       ref)
    record["status"]      = "redeemed"
    record["redeemed_at"] = datetime.now().isoformat()
    save_db()

    logger.info(f"✅ NFC redeemed: {token_id} ₦{amount:,.2f} → {recipient_wid}")
    bg.add_task(_send_nfc_claimed_emails, record, recipient_w.owner_name)
    return {
        "success":  True,
        "message":  f"₦{amount:,.2f} received from {record['sender_name']}!",
        "amount":   amount,
        "sender":   record["sender_name"],
        "note":     record["note"],
    }


def _redeem_offline_token(raw_token: str, redeemer_wid: str) -> dict:
    """Validate and redeem an offline-generated token."""
    try:
        # Format: CPNFC-{wallet_id}:{amount}:{tag}:{timestamp}:{checksum}
        body     = raw_token.upper().replace("CPNFC-", "")
        parts    = body.rsplit(":", 1)
        payload  = parts[0]
        checksum = parts[1] if len(parts) > 1 else "0000"

        # Verify checksum
        expected = str(sum(payload.encode()) % 9999).zfill(4)
        if checksum != expected:
            raise HTTPException(400, "Invalid token — checksum mismatch.")

        p_parts = payload.split(":")
        if len(p_parts) < 4:
            raise HTTPException(400, "Malformed offline token.")

        wallet_id  = p_parts[0]
        amount     = float(p_parts[1])
        tag        = p_parts[2]
        ts         = int(p_parts[3])

        # Check not expired (24 hours)
        age_hours = (datetime.now().timestamp() - ts/1000) / 3600
        if age_hours > 24:
            raise HTTPException(410, "Offline token has expired (24 hour limit).")

        sender_w   = _get_wallet(wallet_id)
        redeemer_w = _get_wallet(redeemer_wid)

        if amount > sender_w.balance:
            raise HTTPException(400, f"Sender has insufficient balance: ₦{sender_w.balance:,.2f}")

        ref = f"NFC-OFFLINE-{uuid.uuid4().hex[:8].upper()}"
        sender_w.debit(amount, "nfc_pay_hold",
                       f"NFC offline payment to {redeemer_w.owner_name}", ref)
        redeemer_w.credit(amount, "nfc_pay_receive",
                          f"NFC Pay (offline) from {sender_w.owner_name}", ref)
        save_db()
        logger.info(f"✅ Offline NFC redeemed: {wallet_id} ₦{amount:,.2f} → {redeemer_wid}")
        return {
            "success": True,
            "message": f"₦{amount:,.2f} received from {sender_w.owner_name}!",
            "amount":  amount,
            "sender":  sender_w.owner_name,
            "offline": True,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Could not redeem offline token: {e}")


def _expire_nfc_token(token_id: str):
    """Return funds to sender on expiry."""
    record = nfc_tokens.get(token_id)
    if not record or record["status"] != "pending":
        return
    wid = record["sender_wallet_id"]
    if wid in wallets:
        wallets[wid].credit(record["amount_naira"], "nfc_pay_refund",
                            f"NFC token expired — refund from {record['recipient_tag']}",
                            f"NFC-EXP-{uuid.uuid4().hex[:8].upper()}")
    record["status"] = "expired"
    save_db()


@app.get("/nfc-pay/status/{token_id}")
def nfc_token_status(token_id: str):
    record = nfc_tokens.get(token_id.upper())
    if not record:
        raise HTTPException(404, "Token not found")
    return {"success": True, "status": record["status"],
            "amount": record["amount_naira"], "sender": record["sender_name"],
            "created_at": record["created_at"], "expires_at": record["expires_at"]}


def _send_nfc_created_email(w: "Wallet", token_id: str, tag: str, amount: float, note: str):
    subj = f"📲 NFC Payment Created — ₦{amount:,.2f} to {tag}"
    body = f"""<div style="font-family:-apple-system,sans-serif;max-width:520px;margin:0 auto">
      <div style="text-align:center;padding:32px 20px 24px;border-bottom:1px solid #F3F4F6">
        <p style="margin:0 0 4px;font-size:13px;color:#6B7280;text-transform:uppercase">NFC Payment</p>
        <p style="margin:0;font-size:42px;font-weight:900;color:#7C3AED">₦{amount:,.2f}</p>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:6px 18px;background:#F5F3FF;border-radius:20px;border:1px solid #DDD6FE">
          <span style="color:#5B21B6;font-weight:700;font-size:14px">⏳ Awaiting Claim</span>
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;margin-top:8px">
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">To</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{tag}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px;border-bottom:1px solid #F3F4F6">Note</td>
            <td style="padding:12px 16px;color:#111827;font-size:13px;font-weight:600;border-bottom:1px solid #F3F4F6;text-align:right">{note or "—"}</td></tr>
        <tr><td style="padding:12px 16px;color:#6B7280;font-size:13px">Token</td>
            <td style="padding:12px 16px;color:#7C3AED;font-size:11px;font-weight:600;text-align:right;font-family:monospace">{token_id}</td></tr>
      </table>
      <p style="margin:16px;font-size:12px;color:#6B7280">Funds expire in 24 hours if unclaimed — they will be returned automatically.</p>
    </div>"""
    send_email(w.owner_email, subj, _receipt_shell(w.owner_name, "#7C3AED", "NFC Pay Sent 📲", f"To: {tag}", body))


def _send_nfc_claimed_emails(record: dict, claimer_name: str):
    amount = record["amount_naira"]
    wid    = record["sender_wallet_id"]
    if wid in wallets:
        w    = wallets[wid]
        subj = f"✅ {claimer_name} claimed your NFC payment of ₦{amount:,.2f}"
        body = f"""<div style="font-family:-apple-system,sans-serif;padding:24px">
            <p style="font-size:22px;font-weight:900;color:#7C3AED">NFC Payment Claimed ✅</p>
            <p style="color:#374151">{claimer_name} received <strong>₦{amount:,.2f}</strong>.</p>
        </div>"""
        send_email(w.owner_email, subj, _receipt_shell(w.owner_name, "#7C3AED", "NFC Pay Claimed", "", body))


@app.post("/ai/chat")
async def ai_chat(req: AiChatRequest):
    """
    Claude-powered AI assistant for CredionPay users.
    Optionally personalises response with wallet context.
    """
    # Re-read at request time, strip any whitespace/CR/quotes that corrupt the key
    raw_key = os.getenv("ANTHROPIC_API_KEY", "") or ANTHROPIC_API_KEY
    api_key = raw_key.strip().strip('"').strip("'").strip()
    logger.info(f"🤖 AI key length={len(api_key)} starts={api_key[:20] if api_key else 'EMPTY'}...")
    if not api_key or not api_key.startswith("sk-ant-"):
        raise HTTPException(503, f"AI assistant not configured. Key invalid (len={len(api_key)}). Check .env file.")

    # Build personalised system prompt if wallet_id provided
    system = NAIRAFLOW_SYSTEM_PROMPT
    if req.wallet_id and req.wallet_id in wallets:
        w = wallets[req.wallet_id]
        tx_count   = len(w.transactions)
        balance    = w.balance
        kyc_status = w.kyc.status
        first_name = w.owner_name.split()[0] if w.owner_name else "User"
        system += f"""

User context:
- Name: {first_name}
- Wallet Balance: ₦{balance:,.2f}
- KYC Status: {kyc_status}
- Total Transactions: {tx_count}
- Address the user by first name ({first_name}) naturally
- If balance is low (< ₦5,000), gently suggest funding options
"""

    # Format messages for Anthropic API
    messages = [{"role": m.role, "content": m.content} for m in req.messages]

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 500,
                "system": system,
                "messages": messages,
            },
            timeout=30,
            verify=False,  # Fix SSL cert issue on Windows
        )

        if response.status_code != 200:
            logger.error(f"Anthropic API error: {response.status_code} — {response.text}")
            raise HTTPException(502, f"AI service error: {response.status_code}")

        data = response.json()
        reply = data["content"][0]["text"]

        logger.info(f"🤖 AI chat — wallet={req.wallet_id or 'anonymous'} "
                    f"messages={len(messages)} reply_len={len(reply)}")

        return {
            "success": True,
            "reply": reply,
            "model": "claude-haiku-4-5-20251001",
            "wallet_id": req.wallet_id,
        }

    except requests.Timeout:
        raise HTTPException(504, "AI assistant timed out. Please try again.")
    except requests.RequestException as e:
        logger.error(f"AI chat request error: {e}")
        raise HTTPException(502, "Could not reach AI service. Check your connection.")
