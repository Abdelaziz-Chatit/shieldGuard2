from fastapi import FastAPI, HTTPException, Depends, Header, Response, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, model_validator
from keras.models import load_model
import json
import numpy as np
import re
import os
import glob
import hashlib
import secrets
import subprocess
import sys
from pathlib import Path
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, or_
from sqlalchemy.ext.declarative import declarative_base

def normalize_domain(domain: str) -> str:
    domain = (domain or "").strip()
    if not domain:
        return ""
    if not domain.startswith(("http://", "https://")):
        domain = "http://" + domain
    parsed = urlparse(domain)
    host = parsed.hostname or parsed.path or ""
    host = host.lower().strip().strip('.')
    if host.startswith('www.'):
        host = host[4:]
    return host
from sqlalchemy.orm import sessionmaker
import datetime

try:
    import joblib
    _joblib_load = joblib.load
except ImportError:
    import pickle
    _joblib_load = lambda path: pickle.load(open(path, 'rb'))

Base = declarative_base()

class WhitelistRequest(Base):
    __tablename__ = 'whitelist_requests'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True)
    user_id = Column(String(255))
    requested_at = Column(DateTime, default=datetime.datetime.utcnow)
    approved = Column(Boolean, default=False)
    approved_at = Column(DateTime, nullable=True)
    expiry = Column(DateTime, nullable=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default='user')
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    lockout_until = Column(DateTime, nullable=True)

class AuthToken(Base):
    __tablename__ = 'auth_tokens'
    id = Column(Integer, primary_key=True)
    token = Column(String(128), unique=True, nullable=False)
    user_id = Column(Integer, nullable=False)
    expires_at = Column(DateTime, nullable=True)

# New models for proxy-based system
class WhitelistEntry(Base):
    __tablename__ = 'whitelist'
    domain = Column(String(255), primary_key=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    added_by = Column(String(255), default='admin')

class BlacklistEntry(Base):
    __tablename__ = 'blacklist'
    domain = Column(String(255), primary_key=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    added_by = Column(String(255), default='admin')


class TemporaryUnblock(Base):
    """Temporary unblock record created when an admin approves an access request.
    These entries temporarily exempt a blacklisted domain from blocking until `expires_at`.
    """
    __tablename__ = 'temporary_unblocks'
    domain = Column(String(255), primary_key=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    added_by = Column(String(255), default='admin')

class AccessRequest(Base):
    __tablename__ = 'access_requests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False)
    reason = Column(String(500))
    requested_duration_minutes = Column(Integer, nullable=True)
    requested_by = Column(String(255), nullable=False, default='unknown')
    status = Column(String(50), default='pending')  # pending | approved | rejected
    rejection_reason = Column(String(500), nullable=True)
    requested_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

class Notification(Base):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    target_role = Column(String(50), nullable=False, default='all')
    target_user = Column(String(255), nullable=True)
    type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(String(1000), nullable=False)
    severity = Column(String(50), nullable=False, default='info')
    read = Column(Boolean, default=False)
    metadata_json = Column('metadata', String(2000), nullable=True)

class AuditLog(Base):
    __tablename__ = 'security_audit_log'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    actor_username = Column(String(255), nullable=True)
    action = Column(String(255), nullable=False)
    target = Column(String(255), nullable=True)
    ip_address = Column(String(100), nullable=True)
    result = Column(String(255), nullable=True)

class NetworkEvent(Base):
    __tablename__ = 'network_events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String(100), nullable=True)
    dst_ip = Column(String(100), nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(50), nullable=True)
    score = Column(Float, nullable=True)
    is_suspicious = Column(Boolean, default=False)
    label_text = Column(String(255), nullable=True)
    raw_features_json = Column(String(4000), nullable=True)

# Database setup - using SQLite for testing, change to MySQL when ready
DATABASE_URL = "sqlite:///./shieldguard.db"  # For testing
# DATABASE_URL = "mysql+mysqlconnector://root:YOUR_PASSWORD@localhost/shieldguard"  # For production
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)
START_TIME = datetime.datetime.utcnow()

app = FastAPI(title="ShieldGuard Backend", description="Phishing detection and DNS management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] ,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Background task to clean expired whitelist entries
@app.on_event("startup")
async def startup_event():
    import asyncio

    async def cleanup_expired():
        while True:
            db = SessionLocal()
            try:
                now = datetime.datetime.utcnow()
                # Clean expired whitelist entries (legacy) and temporary unblocks
                expired_whitelist = db.query(WhitelistEntry).filter(WhitelistEntry.expires_at != None, WhitelistEntry.expires_at < now).all()
                for entry in expired_whitelist:
                    db.delete(entry)

                expired_temp = db.query(TemporaryUnblock).filter(TemporaryUnblock.expires_at != None, TemporaryUnblock.expires_at < now).all()
                for entry in expired_temp:
                    existing_black = db.query(BlacklistEntry).filter(BlacklistEntry.domain == entry.domain).first()
                    if not existing_black:
                        db.add(BlacklistEntry(domain=entry.domain, added_by='system_reblock'))
                        db.add(Notification(
                            target_role='admin',
                            type='TEMPORARY_ACCESS_EXPIRED',
                            title='Temporary access expired',
                            message=f'Temporary access for {entry.domain} has expired and was re-blocked',
                            severity='warning',
                            read=False,
                            metadata_json=json.dumps({'domain': entry.domain})
                        ))
                    db.delete(entry)

                total_cleaned = len(expired_whitelist) + len(expired_temp)
                if total_cleaned:
                    db.commit()
                    print(f"Cleaned up {total_cleaned} expired entries (whitelist/temp unblocks)")
            except Exception as e:
                print(f"Error cleaning up expired entries: {e}")
                try:
                    db.rollback()
                except Exception:
                    pass
            finally:
                db.close()
            await asyncio.sleep(60)  # Run every minute

    asyncio.create_task(cleanup_expired())
    try:
        start_network_pipeline()
        print('Started network pipeline subprocess during startup')
    except Exception as e:
        print(f'Unable to start network pipeline on startup: {e}')

# Load char_cnn model
base_dir = os.path.dirname(__file__)
vocab_path = os.path.join(base_dir, 'models', 'char_cnn', 'vocab.json')
with open(vocab_path, 'r') as f:
    vocab = json.load(f)

model_char_cnn = None
model_cnn_gru = None

try:
    model_char_cnn_path = os.path.join(base_dir, 'models', 'char_cnn', 'model_converted.keras')
    if not os.path.exists(model_char_cnn_path):
        model_char_cnn_path = os.path.join(base_dir, 'models', 'char_cnn', 'model.keras')
    model_char_cnn = load_model(model_char_cnn_path)
except Exception as e:
    print(f"Failed to load char_cnn model: {e}")

try:
    model_cnn_gru_path = os.path.join(base_dir, 'models', 'cnn_gru', 'model_converted.keras')
    if not os.path.exists(model_cnn_gru_path):
        model_cnn_gru_path = os.path.join(base_dir, 'models', 'cnn_gru', 'model.keras')
    model_cnn_gru = load_model(model_cnn_gru_path)
except Exception as e:
    print(f"Failed to load cnn_gru model: {e}")

if_model = None
if_scaler = None
if_features = None
if_selected_feature_names = None
if_selected_feature_indices = None
signature_db = []

signature_db_path = os.path.join(base_dir, 'signatures', 'known_signatures.json')
if not os.path.exists(signature_db_path):
    os.makedirs(os.path.dirname(signature_db_path), exist_ok=True)
    with open(signature_db_path, 'w', encoding='utf-8') as f:
        json.dump({
            "known_signatures": [
                {
                    "id": "example_phishing_signature",
                    "pattern": "deadbeefcafebabe",
                    "description": "Example known malicious signature pattern. Replace this with real signatures."
                }
            ]
        }, f, indent=2)

SIGNATURE_IOC_FOLDER = os.path.join(base_dir, 'signatures', 'iocs')


def normalize_signature(value: str) -> str:
    return ''.join(str(value).strip().lower().split())


def parse_ioc_text_file(path: str, kind: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ' ' in line and not line.startswith(('http://', 'https://')):
                continue
            if kind == 'hash':
                if not re.fullmatch(r'[0-9A-Fa-f]{32,128}', line):
                    continue
            if kind == 'c2':
                if line.startswith(('http://', 'https://')):
                    pattern = line
                elif re.fullmatch(r'\d+\.\d+\.\d+\.\d+', line) or '.' in line:
                    pattern = line
                else:
                    continue
            else:
                pattern = line
            normalized = normalize_signature(pattern)
            if not normalized:
                continue
            entries.append({
                'id': f'{kind}-{normalized[:32]}',
                'pattern': pattern,
                'description': f'Imported from Signature-Base {os.path.basename(path)}'
            })
    return entries


def load_signature_db() -> List[Dict[str, str]]:
    loaded: List[Dict[str, str]] = []
    seen: set = set()

    try:
        with open(signature_db_path, 'r', encoding='utf-8') as f:
            base_list = json.load(f).get('known_signatures', [])
            for entry in base_list:
                normalized = normalize_signature(entry.get('pattern', ''))
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    loaded.append(entry)
    except Exception as e:
        print(f'Failed to load signature database: {e}')

    if os.path.isdir(SIGNATURE_IOC_FOLDER):
        for ioc_path in glob.glob(os.path.join(SIGNATURE_IOC_FOLDER, '*.txt')):
            kind = 'generic'
            name = os.path.basename(ioc_path).lower()
            if 'keyword' in name:
                kind = 'keywords'
            elif 'c2' in name:
                kind = 'c2'
            elif 'filename' in name:
                kind = 'filename'
            elif 'hash' in name:
                kind = 'hash'
            for entry in parse_ioc_text_file(ioc_path, kind):
                normalized = normalize_signature(entry['pattern'])
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    loaded.append(entry)

    return loaded


signature_db = load_signature_db()

try:
    if_features_path = os.path.join(base_dir, 'models', 'isolation_forest', 'features.pkl')
    if_scaler_path = os.path.join(base_dir, 'models', 'isolation_forest', 'scaler.pkl')
    if_model_path = os.path.join(base_dir, 'models', 'isolation_forest', 'model.pkl')
    if_report_path = os.path.join(base_dir, 'models', 'isolation_forest', 'if_report.json')
    if_features = _joblib_load(if_features_path)
    if_scaler = _joblib_load(if_scaler_path)
    if_model = _joblib_load(if_model_path)
    if os.path.exists(if_report_path):
        with open(if_report_path, 'r', encoding='utf-8') as report_file:
            report = json.load(report_file)
        report_features = report.get('architecture', {}).get('top_features')
        if isinstance(report_features, list) and report_features:
            if_selected_feature_names = report_features
            if_selected_feature_indices = [if_features.index(name) for name in if_selected_feature_names if name in if_features]
except Exception as e:
    print(f"Failed to load isolation forest packet model: {e}")

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    username: str
    role: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = 'user'

class ScanRequest(BaseModel):
    path: str
    scan_type: Optional[str] = 'partial'

class DeviceScanRequest(BaseModel):
    path: str
    device_name: Optional[str] = None

class WhitelistRequestPayload(BaseModel):
    domain: str
    duration_hours: Optional[int] = 24

class DNSLookupRequest(BaseModel):
    domain: str

class ApproveRequestPayload(BaseModel):
    duration_hours: int

class WhitelistAddRequest(BaseModel):
    domain: str
    duration_minutes: Optional[int] = None

class AccessRequestCreate(BaseModel):
    domain: str
    reason: Optional[str] = None
    requested_duration_minutes: Optional[int] = None

class AccessRequestApprove(BaseModel):
    # Accept fractional hours (floats) so UI can request short durations (e.g., 1 minute = 0.0167 hours)
    duration_hours: Optional[float] = None

class AccessRequestReject(BaseModel):
    rejection_reason: str


# Optional bcrypt support for stronger password hashing.
try:
    import bcrypt
    _bcrypt_available = True
except ImportError:
    _bcrypt_available = False

PIPELINE_STATUS_FILE = os.path.join(base_dir, 'pipeline_status.json')
PIPELINE_LOG_DIR = os.path.join(base_dir, 'logs')
pipeline_process = None


def hash_password(password: str) -> str:
    if _bcrypt_available:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return 'sha256$' + hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith('sha256$'):
        expected = password_hash.split('$', 1)[1]
        if hashlib.sha256(password.encode('utf-8')).hexdigest() == expected:
            return True
        return False
    if _bcrypt_available:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    return False


def maybe_rehash_password(db, user: User, password: str):
    if not _bcrypt_available:
        return
    if user.password_hash.startswith('sha256$'):
        user.password_hash = hash_password(password)
        db.add(user)
        db.commit()


def create_notification(db, target_role: str, type: str, title: str, message: str, severity: str = 'info', target_user: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
    notif = Notification(
        target_role=target_role,
        target_user=target_user,
        type=type,
        title=title,
        message=message,
        severity=severity,
        read=False,
        metadata_json=json.dumps(metadata or {})
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)
    return notif


def log_audit(db, actor_username: Optional[str], action: str, target: Optional[str] = None, ip_address: Optional[str] = None, result: Optional[str] = None):
    audit = AuditLog(
        actor_username=actor_username,
        action=action,
        target=target,
        ip_address=ip_address,
        result=result
    )
    db.add(audit)
    db.commit()
    return audit


def ensure_default_admin():
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.role == 'admin').first()
        if not admin_user:
            default_admin = User(username='admin', password_hash=hash_password('admin123'), role='admin', created_by='system')
            db.add(default_admin)
            db.commit()
            print('Created default admin account: admin / admin123')
    finally:
        db.close()


def ensure_access_request_user_column():
    if engine.dialect.name == 'sqlite':
        try:
            conn = engine.raw_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(access_requests);")
            columns = [row[1] for row in cursor.fetchall()]
            if 'requested_by' not in columns:
                cursor.execute("ALTER TABLE access_requests ADD COLUMN requested_by VARCHAR(255) DEFAULT 'unknown';")
                conn.commit()
                print('Added requested_by column to access_requests table')

            cursor.execute("PRAGMA table_info(users);")
            user_columns = [row[1] for row in cursor.fetchall()]
            if 'failed_login_attempts' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;")
                conn.commit()
                print('Added failed_login_attempts column to users table')
            if 'lockout_until' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN lockout_until DATETIME NULL;")
                conn.commit()
                print('Added lockout_until column to users table')
        except Exception as e:
            print(f'Unable to ensure database compatibility: {e}')
        finally:
            conn.close()

ensure_access_request_user_column()
ensure_default_admin()


def create_token() -> str:
    return secrets.token_urlsafe(32)


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail='Missing authorization header')
    token = authorization.replace('Bearer ', '').strip()
    if not token:
        raise HTTPException(status_code=401, detail='Invalid authorization header')
    db = SessionLocal()
    try:
        auth = db.query(AuthToken).filter(AuthToken.token == token, AuthToken.expires_at > datetime.datetime.utcnow()).first()
        if not auth:
            raise HTTPException(status_code=401, detail='Invalid or expired token')
        user = db.query(User).filter(User.id == auth.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail='User not found')
        return user
    finally:
        db.close()


def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role.lower() != 'admin':
        raise HTTPException(status_code=403, detail='Admin privileges required')
    return current_user


class URLRequest(BaseModel):
    url: str

class PacketRequest(BaseModel):
    features: Dict[str, float]
    threshold: Optional[float] = None

    @model_validator(mode='before')
    def wrap_root_payload(cls, values):
        if isinstance(values, dict) and 'features' not in values and 'threshold' not in values:
            return {'features': values}
        return values

class SignatureCompareRequest(BaseModel):
    signature: str
    signature_type: Optional[str] = None

    @model_validator(mode='before')
    def accept_content_alias(cls, values):
        if isinstance(values, dict) and 'signature' not in values and 'content' in values:
            values['signature'] = values.pop('content')
        return values


def compare_signature_similarity(candidate: str, known: str) -> float:
    return float(SequenceMatcher(None, candidate, known).ratio())


def extract_signature_pattern(pattern_raw: str) -> str:
    if not isinstance(pattern_raw, str):
        return ''
    cleaned = pattern_raw.strip()
    if ';' in cleaned:
        cleaned = cleaned.split(';', 1)[0]
    return cleaned


def is_hex_string(value: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]{32,128}', value.strip()))


def calculate_signature_match_score(candidate: str, entry: Dict[str, Any]) -> float:
    if not isinstance(candidate, str) or not candidate:
        return 0.0

    candidate_text = candidate.strip()
    normalized_candidate = normalize_signature(candidate_text)
    candidate_lower = candidate_text.lower()
    entry_id = (entry.get('id') or '').lower()
    pattern_raw = extract_signature_pattern(entry.get('pattern', '') or '')
    if not pattern_raw:
        return 0.0

    normalized_pattern = normalize_signature(pattern_raw)
    pattern_lower = pattern_raw.lower()

    if entry_id.startswith('hash'):
        if is_hex_string(normalized_candidate):
            if normalized_candidate == normalized_pattern or normalized_candidate.startswith(normalized_pattern) or normalized_pattern.startswith(normalized_candidate):
                return 1.0
        if normalized_pattern and normalized_pattern in normalized_candidate:
            return 1.0

    if entry_id.startswith('filename') or entry_id.startswith('keyword'):
        if normalized_pattern and normalized_pattern in normalized_candidate:
            return 1.0
        if pattern_lower and pattern_lower in candidate_lower:
            return 1.0

    if entry_id.startswith('ip') or entry_id.startswith('c2') or entry_id.startswith('domain'):
        if pattern_lower and pattern_lower in candidate_lower:
            return 1.0
        if normalized_pattern and normalized_pattern in normalized_candidate:
            return 1.0

    if pattern_lower and pattern_lower in candidate_lower:
        return 1.0
    if normalized_pattern and normalized_pattern in normalized_candidate:
        return 1.0

    try:
        regex = re.compile(pattern_raw, re.IGNORECASE)
        if regex.search(candidate_text):
            return 1.0
    except re.error:
        pass

    # Avoid expensive fuzzy matching on large binary-derived content.
    if len(candidate_text) > 200_000:
        return 0.0

    return compare_signature_similarity(normalized_candidate, normalized_pattern)


def build_packet_vector(features: Dict[str, float]) -> np.ndarray:
    if if_features is None:
        raise RuntimeError('Isolation forest packet feature list is not loaded.')
    missing = [f for f in if_features if f not in features]
    if missing:
        raise ValueError(f'Missing packet features: {missing}')
    values = [float(features[f]) for f in if_features]
    return np.array(values, dtype=float).reshape(1, -1)


def collect_network_metrics() -> Dict[str, float]:
    stats: Dict[str, float] = {}
    try:
        if os.name == 'nt':
            import subprocess
            output = subprocess.check_output(['netstat', '-e'], universal_newlines=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = re.split(r'\s{2,}', line)
                if len(parts) >= 2 and parts[0].isalpha():
                    for idx, raw_value in enumerate(parts[1:], start=1):
                        if raw_value.replace(',', '').isdigit():
                            name = f"{parts[0].strip().lower().replace(' ', '_')}_{idx}"
                            stats[name] = float(raw_value.replace(',', ''))
        else:
            import subprocess
            output = subprocess.check_output(['netstat', '-s'], universal_newlines=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = re.match(r'^(\d+)\s+(.+)$', line)
                if match:
                    name = match.group(2).strip().lower().replace(' ', '_')
                    stats[name] = float(match.group(1))
    except Exception:
        pass
    return stats


def preprocess_url_char(url, max_len=200):
    url = url.lower()
    url = re.sub(r'http[s]?://', '', url)
    chars = list(url)
    indices = [vocab.get(c, vocab['<UNK>']) for c in chars]
    if len(indices) < max_len:
        indices += [vocab['<PAD>']] * (max_len - len(indices))
    else:
        indices = indices[:max_len]
    return np.array(indices).reshape(1, -1)

def preprocess_url_gru(url, max_len=68):
    url = url.lower()
    url = re.sub(r'http[s]?://', '', url)
    chars = list(url)
    indices = [vocab.get(c, vocab['<UNK>']) for c in chars]
    if len(indices) < max_len:
        indices += [vocab['<PAD>']] * (max_len - len(indices))
    else:
        indices = indices[:max_len]
    return np.array(indices).reshape(1, max_len, 1)

@app.post("/predict_phishing")
async def predict_phishing(request: URLRequest):
    try:
        if model_char_cnn is None or model_cnn_gru is None:
            raise RuntimeError("Model files are not loaded. Check backend model paths.")

        processed_char = preprocess_url_char(request.url)
        processed_gru = preprocess_url_gru(request.url)

        pred_char = model_char_cnn.predict(processed_char)[0]
        if pred_char.shape[-1] == 2:
            pred_char_score = float(pred_char[1])
        else:
            pred_char_score = float(pred_char[0])

        pred_gru_score = float(model_cnn_gru.predict(processed_gru)[0][0])

        score = (pred_char_score + pred_gru_score) / 2
        final_score = float(np.clip(score, 0.0, 1.0))
        # Lowered phishing detection threshold from 0.5 to 0.4
        is_phishing = final_score >= 0.4
        return {
            "score": final_score,
            "is_phishing": bool(is_phishing),
            "char_model": pred_char_score,
            "gru_model": pred_gru_score
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict_network")
async def predict_network(request: PacketRequest):
    try:
        if if_model is None or if_scaler is None or if_features is None:
            raise RuntimeError("Isolation forest network packet model is unavailable.")

        vector = build_packet_vector(request.features)
        scaled = if_scaler.transform(vector)
        if if_selected_feature_indices:
            selected_scaled = scaled[:, if_selected_feature_indices]
        else:
            selected_scaled = scaled
        raw_score = float(if_model.score_samples(selected_scaled)[0])
        threat_score = float(1.0 / (1.0 + np.exp(raw_score)))
        threshold = request.threshold if request.threshold is not None else 0.6161
        threshold = float(threshold) if 0.0 <= threshold <= 1.0 else 0.6161
        model_prediction = int(if_model.predict(selected_scaled)[0])
        label_text = 'Suspicious traffic' if model_prediction == 1 else 'Normal traffic'
        return {
            "score": threat_score,
            "is_suspicious": threat_score >= threshold,
            "anomaly_label": model_prediction,
            "label_text": label_text,
            "raw_score": raw_score,
            "threshold": threshold,
            "required_features": if_features,
            "selected_features": if_selected_feature_names or []
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/network_features")
async def network_features():
    metrics = collect_network_metrics()
    return {
        "features": if_features or [],
        "actual": {feature: metrics.get(feature, 0.0) for feature in (if_features or [])},
        "raw_metrics": metrics
    }


def _load_pipeline_status():
    try:
        if os.path.exists(PIPELINE_STATUS_FILE):
            with open(PIPELINE_STATUS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {"running": False, "packets_captured": 0, "uptime_seconds": 0, "packets_per_second": 0.0, "last_updated": None}


def _write_pipeline_status(status: dict):
    try:
        os.makedirs(os.path.dirname(PIPELINE_STATUS_FILE), exist_ok=True)
        with open(PIPELINE_STATUS_FILE, 'w', encoding='utf-8') as f:
            json.dump(status, f)
    except Exception:
        pass


def _ensure_pipeline_log_dir():
    os.makedirs(PIPELINE_LOG_DIR, exist_ok=True)


def start_network_pipeline():
    global pipeline_process
    if pipeline_process and pipeline_process.poll() is None:
        return pipeline_process
    _ensure_pipeline_log_dir()
    pipeline_path = os.path.join(base_dir, 'packet_pipeline.py')
    if not os.path.exists(pipeline_path):
        raise RuntimeError('packet_pipeline.py file not found')
    log_file = open(os.path.join(PIPELINE_LOG_DIR, 'pipeline.log'), 'a', encoding='utf-8')
    pipeline_process = subprocess.Popen([sys.executable, pipeline_path], cwd=base_dir, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    return pipeline_process


def stop_network_pipeline():
    global pipeline_process
    if not pipeline_process:
        return
    try:
        pipeline_process.terminate()
        pipeline_process.wait(timeout=5)
    except Exception:
        try:
            pipeline_process.kill()
        except Exception:
            pass
    finally:
        pipeline_process = None


@app.get("/network/pipeline/status")
async def network_pipeline_status(current_user: User = Depends(get_current_user)):
    status = _load_pipeline_status()
    if status.get('last_updated') is None:
        status['last_updated'] = datetime.datetime.utcnow().isoformat()
    return status


@app.post("/network/pipeline/start")
async def network_pipeline_start(current_user: User = Depends(get_current_admin)):
    try:
        start_network_pipeline()
        return {"status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/network/pipeline/stop")
async def network_pipeline_stop(current_user: User = Depends(get_current_admin)):
    stop_network_pipeline()
    return {"status": "stopped"}


@app.get("/network/live-feed")
async def network_live_feed(current_user: User = Depends(get_current_user), limit: int = 100, filter: str = 'all'):
    db = SessionLocal()
    try:
        query = db.query(NetworkEvent).order_by(NetworkEvent.timestamp.desc())
        if filter == 'suspicious':
            query = query.filter(NetworkEvent.is_suspicious == True)
        elif filter == 'malicious':
            query = query.filter(NetworkEvent.label_text.ilike('%malicious%'))
        events = query.limit(limit).all()
        return [{
            'id': e.id,
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'src_ip': e.src_ip,
            'dst_ip': e.dst_ip,
            'dst_port': e.dst_port,
            'protocol': e.protocol,
            'score': e.score,
            'is_suspicious': e.is_suspicious,
            'label_text': e.label_text,
            'raw_features_json': json.loads(e.raw_features_json or '{}')
        } for e in events]
    finally:
        db.close()


@app.get("/network/stats")
async def network_stats(current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        total = db.query(NetworkEvent).count()
        threats = db.query(NetworkEvent).filter(NetworkEvent.is_suspicious == True).count()
        benign = total - threats
        status = _load_pipeline_status()
        return {
            'total': total,
            'threats': threats,
            'benign': benign,
            'last_updated': status.get('last_updated'),
            'packets_per_second': status.get('packets_per_second', 0.0)
        }
    finally:
        db.close()


@app.post("/login")
async def login(credentials: LoginRequest):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == credentials.username).first()
        now = datetime.datetime.utcnow()
        if user and user.lockout_until and user.lockout_until > now:
            raise HTTPException(status_code=429, detail="Account locked due to too many failed login attempts. Try again later.")

        if not user or not verify_password(credentials.password, user.password_hash):
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 10:
                    user.lockout_until = now + datetime.timedelta(minutes=15)
                    create_notification(db, target_role='admin', type='LOGIN_FAILED', title='Login lockout triggered', message=f'User {user.username} is locked out until {user.lockout_until.isoformat()}', severity='warning', metadata={'user': user.username})
                    log_audit(db, user.username, 'login_lockout', target=user.username, result='locked_out')
                else:
                    log_audit(db, user.username, 'login_failed', target=user.username, result=f'failed_{user.failed_login_attempts}')
                db.commit()
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.failed_login_attempts:
            user.failed_login_attempts = 0
            user.lockout_until = None
            db.add(user)
        maybe_rehash_password(db, user, credentials.password)

        token = create_token()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        auth_token = AuthToken(token=token, user_id=user.id, expires_at=expires_at)
        db.add(auth_token)
        db.commit()
        log_audit(db, user.username, 'login_success', target=user.username, result='success')
        return {"token": token, "username": user.username, "role": user.role}
    finally:
        db.close()

@app.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role, "created_by": current_user.created_by}

@app.get("/users")
async def list_users(current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return [{"id": u.id, "username": u.username, "role": u.role, "created_by": u.created_by, "created_at": u.created_at} for u in users]
    finally:
        db.close()

@app.get("/admin/users")
async def admin_list_users(current_user: User = Depends(get_current_admin)):
    return await list_users(current_user)

@app.post("/admin/create_user")
async def create_user(request: CreateUserRequest, current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == request.username).first():
            raise HTTPException(status_code=400, detail="Username already exists")
        user = User(username=request.username, password_hash=hash_password(request.password), role=request.role, created_by=current_user.username)
        db.add(user)
        db.commit()
        db.refresh(user)
        create_notification(db, target_role='admin', type='USER_CREATED', title='User created', message=f'Admin {current_user.username} created account {user.username}', severity='info', metadata={'user': user.username})
        log_audit(db, current_user.username, 'create_user', target=user.username, result='created')
        return {"id": user.id, "username": user.username, "role": user.role}
    finally:
        db.close()

@app.post("/admin/delete_user/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.username == current_user.username:
            raise HTTPException(status_code=400, detail="Cannot delete the current admin account")
        if user.created_by != current_user.username:
            raise HTTPException(status_code=403, detail="Admins can only delete users they created")
        username = user.username
        db.delete(user)
        db.commit()
        create_notification(db, target_role='admin', type='USER_DELETED', title='User deleted', message=f'Admin {current_user.username} deleted account {username}', severity='info', metadata={'user': username})
        log_audit(db, current_user.username, 'delete_user', target=username, result='deleted')
        return {"status": "deleted"}
    finally:
        db.close()

@app.post("/admin/decline/{request_id}")
async def decline_request(request_id: int, current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        request = db.query(WhitelistRequest).filter(WhitelistRequest.id == request_id).first()
        if not request:
            raise HTTPException(status_code=404, detail="Request not found")
        db.delete(request)
        db.commit()
        create_notification(db, target_role='admin', type='ACCESS_REQUEST_REJECTED', title='Whitelist request declined', message=f'Admin {current_user.username} declined request for {request.domain}', severity='warning', metadata={'domain': request.domain})
        log_audit(db, current_user.username, 'decline_whitelist_request', target=request.domain, result='declined')
        return {"status": "declined"}
    finally:
        db.close()

@app.post("/scan_path")
async def scan_path(request: ScanRequest, current_user: User = Depends(get_current_user)):
    from pathlib import Path
    base_path = Path(request.path)
    if not base_path.exists():
        raise HTTPException(status_code=404, detail="Path does not exist")
    results = []
    scanned_files = 0
    max_depth = 1 if request.scan_type == 'partial' else 999
    for root, _, files in os.walk(base_path):
        depth = len(os.path.relpath(root, base_path).split(os.sep))
        if depth > max_depth:
            continue
        for filename in files:
            scanned_files += 1
            file_path = os.path.join(root, filename)
            result = scan_file_path(file_path)
            if result:
                results.append(result)
    return {"scanned": scanned_files, "findings": results}

@app.post("/scan_file")
async def scan_file(request: ScanRequest, current_user: User = Depends(get_current_user)):
    if not os.path.exists(request.path):
        raise HTTPException(status_code=404, detail="File not found")
    result = scan_file_path(request.path)
    response = {"scanned": 1, "findings": [result] if result else []}
    if result:
        response["steps"] = result.get("steps", [])
    return response

@app.post("/request_whitelist")
async def request_whitelist(payload: WhitelistRequestPayload, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        existing = db.query(WhitelistRequest).filter(WhitelistRequest.domain == payload.domain, WhitelistRequest.approved == False).first()
        if existing:
            raise HTTPException(status_code=400, detail="A whitelist request for this domain already exists.")
        request = WhitelistRequest(domain=payload.domain, user_id=current_user.username)
        db.add(request)
        db.commit()
        db.refresh(request)
        create_notification(db, target_role='admin', type='ACCESS_REQUEST_SUBMITTED', title='Whitelist request submitted', message=f'{current_user.username} requested whitelist access for {payload.domain}', severity='info', metadata={'domain': payload.domain, 'user': current_user.username})
        log_audit(db, current_user.username, 'request_whitelist', target=payload.domain, result='requested')
        return {"status": "requested", "id": request.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.get("/is_whitelisted/{domain}")
async def is_whitelisted(domain: str):
    db = SessionLocal()
    try:
        # Treat "whitelisted" as temporarily unblocked in the new flow
        temp = db.query(TemporaryUnblock).filter(TemporaryUnblock.domain == domain).first()
        if temp:
            expires_at = parse_datetime_value(temp.expires_at)
            if expires_at and expires_at < datetime.datetime.utcnow():
                db.delete(temp)
                db.commit()
                return {"whitelisted": False}
            return {"whitelisted": True, "expires_at": format_iso_utc(expires_at) if expires_at else None}
        return {"whitelisted": False}
    finally:
        db.close()

@app.get("/blocked_sites")
async def get_blocked_sites():
    return RMM_BLOCKED_DOMAINS

@app.get("/pending_requests")
async def pending_requests(current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        requests = db.query(WhitelistRequest).filter(WhitelistRequest.approved == False).all()
        return [{"id": r.id, "domain": r.domain, "user_id": r.user_id, "requested_at": r.requested_at} for r in requests]
    finally:
        db.close()

def _notification_filter_query(db, current_user: User):
    return db.query(Notification).filter(
        or_(Notification.target_role == 'all', Notification.target_role == current_user.role, Notification.target_user == current_user.username)
    )

@app.get("/notifications")
async def notifications(current_user: User = Depends(get_current_user), limit: int = 50, unread_only: bool = False):
    db = SessionLocal()
    try:
        query = _notification_filter_query(db, current_user)
        if unread_only:
            query = query.filter(Notification.read == False)
        notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()
        return [{
            "id": n.id,
            "created_at": n.created_at.isoformat() if n.created_at else None,
            "type": n.type,
            "title": n.title,
            "message": n.message,
            "severity": n.severity,
            "read": n.read,
            "metadata": json.loads(n.metadata_json or '{}')
        } for n in notifications]
    finally:
        db.close()

@app.get("/notifications/feed")
async def notifications_feed(current_user: User = Depends(get_current_user), limit: int = 50, unread_only: bool = False):
    return await notifications(current_user=current_user, limit=limit, unread_only=unread_only)

@app.post("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: int, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            raise HTTPException(status_code=404, detail="Notification not found")
        if notification.target_user and notification.target_user != current_user.username:
            raise HTTPException(status_code=403, detail="Not authorized")
        notification.read = True
        db.add(notification)
        db.commit()
        return {"status": "read"}
    finally:
        db.close()

@app.post("/notifications/read-all")
async def mark_all_notifications_read(current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        query = _notification_filter_query(db, current_user).filter(Notification.read == False)
        for notification in query.all():
            notification.read = True
            db.add(notification)
        db.commit()
        return {"status": "all_read"}
    finally:
        db.close()

@app.get("/notifications/unread-count")
async def unread_notification_count(current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        count = _notification_filter_query(db, current_user).filter(Notification.read == False).count()
        return {"count": count}
    finally:
        db.close()

# New proxy-based endpoints
def format_iso_utc(dt: Optional[datetime.datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + 'Z'
    return dt.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_datetime_value(value: Any) -> Optional[datetime.datetime]:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, str):
        for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
            try:
                return datetime.datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None


def cleanup_expired_temporary_access(db):
    now = datetime.datetime.utcnow()
    expired_temp = []
    for entry in db.query(TemporaryUnblock).filter(TemporaryUnblock.expires_at != None).all():
        expires_at = parse_datetime_value(entry.expires_at)
        if expires_at is None or expires_at < now:
            expired_temp.append(entry)

    if not expired_temp:
        return

    for entry in expired_temp:
        existing_black = db.query(BlacklistEntry).filter(BlacklistEntry.domain == entry.domain).first()
        if not existing_black:
            db.add(BlacklistEntry(domain=entry.domain, added_by='system_reblock'))
            db.add(Notification(
                target_role='admin',
                type='TEMPORARY_ACCESS_EXPIRED',
                title='Temporary access expired',
                message=f'Temporary access for {entry.domain} has expired and was re-blocked',
                severity='warning',
                read=False,
                metadata_json=json.dumps({'domain': entry.domain})
            ))
        db.delete(entry)

    db.commit()

@app.get("/api/whitelist")
async def get_temporary_access_entries():
    """Get active temporary unblock entries"""
    db = SessionLocal()
    try:
        cleanup_expired_temporary_access(db)
        now = datetime.datetime.utcnow()
        entries = db.query(TemporaryUnblock).filter(
            (TemporaryUnblock.expires_at == None) | (TemporaryUnblock.expires_at > now)
        ).all()
        return [{
            "domain": entry.domain,
            "added_at": format_iso_utc(entry.added_at),
            "expires_at": format_iso_utc(entry.expires_at),
            "added_by": entry.added_by
        } for entry in entries]
    finally:
        db.close()

@app.post("/api/whitelist")
async def add_temporary_access(request: WhitelistAddRequest, current_user: User = Depends(get_current_admin)):
    """Add a temporary unblock entry"""
    db = SessionLocal()
    try:
        domain = normalize_domain(request.domain)
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        existing = db.query(TemporaryUnblock).filter(TemporaryUnblock.domain == domain).first()
        if existing:
            raise HTTPException(status_code=400, detail="Domain already has temporary access")

        expires_at = None
        if request.duration_hours is not None and request.duration_hours > 0:
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=request.duration_hours)

        entry = TemporaryUnblock(
            domain=domain,
            expires_at=expires_at,
            added_by=current_user.username
        )
        db.add(entry)
        db.commit()
        create_notification(db, target_role='admin', type='TEMPORARY_ACCESS_ADDED', title='Temporary access granted', message=f'{request.domain} was temporarily unblocked by {current_user.username}', severity='success', metadata={'domain': request.domain, 'expires_at': format_iso_utc(expires_at)})
        log_audit(db, current_user.username, 'add_temporary_access', target=request.domain, result='added')
        return {"status": "added", "domain": request.domain}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.delete("/api/whitelist/{domain}")
async def remove_temporary_access(domain: str, current_user: User = Depends(get_current_admin)):
    """Remove a temporary unblock entry"""
    db = SessionLocal()
    try:
        domain = normalize_domain(domain)
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        entry = db.query(TemporaryUnblock).filter(TemporaryUnblock.domain == domain).first()
        if not entry:
            raise HTTPException(status_code=404, detail="Domain not found in temporary access list")

        # When an admin removes a temporary unblock, re-add the domain to the blacklist
        try:
            existing_black = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
            if not existing_black:
                reentry = BlacklistEntry(domain=domain, added_by=current_user.username)
                db.add(reentry)
                create_notification(db, target_role='admin', type='DOMAIN_BLOCKED', title='Domain blacklisted', message=f'{domain} was re-blocked after temporary access was removed by {current_user.username}', severity='warning', metadata={'domain': domain})
        except Exception:
            # Don't fail removal just because blacklist addition failed
            db.rollback()

        db.delete(entry)
        db.commit()
        create_notification(db, target_role='admin', type='TEMPORARY_ACCESS_REMOVED', title='Temporary access removed', message=f'{domain} was removed from temporary access by {current_user.username}', severity='warning', metadata={'domain': domain})
        log_audit(db, current_user.username, 'remove_temporary_access', target=domain, result='removed')
        return {"status": "removed", "domain": domain}
    finally:
        db.close()

@app.get("/api/blacklist")
async def get_blacklist(current_user: User = Depends(get_current_admin)):
    """Get all blacklisted domains"""
    db = SessionLocal()
    try:
        cleanup_expired_temporary_access(db)
        entries = db.query(BlacklistEntry).all()
        return [{"domain": entry.domain, "added_at": entry.added_at.isoformat(), "added_by": entry.added_by} for entry in entries]
    finally:
        db.close()

@app.post("/api/blacklist")
async def add_to_blacklist(request: dict, current_user: User = Depends(get_current_admin)):
    """Add domain to blacklist"""
    domain = request.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")

    # Normalize the domain: accept full URLs and extract hostname
    try:
        parsed = urlparse(domain)
        host = parsed.hostname or domain
        domain = host.lower().strip()
    except Exception:
        domain = domain.strip().lower()

    db = SessionLocal()
    try:
        existing = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
        if existing:
            raise HTTPException(status_code=400, detail="Domain already in blacklist")

        entry = BlacklistEntry(
            domain=domain,
            added_by=current_user.username
        )
        db.add(entry)
        db.commit()
        create_notification(db, target_role='admin', type='DOMAIN_BLOCKED', title='Domain blacklisted', message=f'{domain} was added to blacklist by {current_user.username}', severity='warning', metadata={'domain': domain})
        log_audit(db, current_user.username, 'add_blacklist', target=domain, result='added')
        return {"status": "added", "domain": domain}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.delete("/api/blacklist/{domain}")
async def remove_from_blacklist(domain: str, current_user: User = Depends(get_current_admin)):
    """Remove domain from blacklist"""
    db = SessionLocal()
    try:
        # Normalize incoming domain parameter
        try:
            parsed = urlparse(domain)
            domain_key = parsed.hostname or domain
            domain_key = domain_key.lower().strip()
        except Exception:
            domain_key = domain.lower().strip()

        entry = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain_key).first()
        if not entry:
            raise HTTPException(status_code=404, detail="Domain not found in blacklist")

        db.delete(entry)
        db.commit()
        create_notification(db, target_role='admin', type='DOMAIN_UNBLOCKED', title='Blacklist entry removed', message=f'{domain} was removed from blacklist by {current_user.username}', severity='info', metadata={'domain': domain})
        log_audit(db, current_user.username, 'remove_blacklist', target=domain, result='removed')
        return {"status": "removed", "domain": domain}
    finally:
        db.close()


@app.delete("/api/blacklist")
async def remove_from_blacklist_query(domain: str = Query(None), current_user: User = Depends(get_current_admin)):
    """Remove domain from blacklist using query parameter (handles full URLs)"""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain query parameter required")
    db = SessionLocal()
    try:
        try:
            parsed = urlparse(domain)
            domain_key = parsed.hostname or domain
            domain_key = domain_key.lower().strip()
        except Exception:
            domain_key = domain.lower().strip()

        entry = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain_key).first()
        if not entry:
            raise HTTPException(status_code=404, detail="Domain not found in blacklist")

        db.delete(entry)
        db.commit()
        create_notification(db, target_role='admin', type='DOMAIN_UNBLOCKED', title='Blacklist entry removed', message=f'{domain_key} was removed from blacklist by {current_user.username}', severity='info', metadata={'domain': domain_key})
        log_audit(db, current_user.username, 'remove_blacklist', target=domain_key, result='removed')
        return {"status": "removed", "domain": domain_key}
    finally:
        db.close()

@app.get("/api/check/{domain}")
async def check_domain(domain: str):
    """Check if domain is allowed (used by proxy addon)"""
    db = SessionLocal()
    try:
        # Normalize domain
        domain = normalize_domain(domain)
        if not domain:
            return {"allowed": True}
        
        # Check temporary unblocks first - these temporarily exempt a blacklisted domain or RMM domain
        temp = db.query(TemporaryUnblock).filter(TemporaryUnblock.domain == domain).first()
        if temp:
            if temp.expires_at and temp.expires_at < datetime.datetime.utcnow():
                try:
                    existing_black = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
                    if not existing_black:
                        reentry = BlacklistEntry(domain=domain, added_by='system_reblock')
                        db.add(reentry)
                        create_notification(db, target_role='admin', type='TEMPORARY_ACCESS_EXPIRED', title='Temporary access expired', message=f'Temporary access for {domain} expired and was re-blocked', severity='warning', metadata={'domain': domain})
                except Exception:
                    db.rollback()
                db.delete(temp)
                db.commit()
            else:
                return {"allowed": True, "temporary_unblock": True, "expires_at": format_iso_utc(temp.expires_at)}

        # Check for temporary unblock subdomain matches
        for temp in db.query(TemporaryUnblock).all():
            temp_domain = temp.domain.lower()
            if domain.endswith('.' + temp_domain):
                if temp.expires_at and temp.expires_at < datetime.datetime.utcnow():
                    try:
                        existing_black = db.query(BlacklistEntry).filter(BlacklistEntry.domain == temp.domain).first()
                        if not existing_black:
                            reentry = BlacklistEntry(domain=temp.domain, added_by='system_reblock')
                            db.add(reentry)
                            create_notification(db, target_role='admin', type='TEMPORARY_ACCESS_EXPIRED', title='Temporary access expired', message=f'Temporary access for {temp.domain} expired and was re-blocked', severity='warning', metadata={'domain': temp.domain})
                    except Exception:
                        db.rollback()
                    db.delete(temp)
                    db.commit()
                    continue
                return {"allowed": True, "temporary_unblock": True, "expires_at": format_iso_utc(temp.expires_at)}

        # Check general blacklist
        blacklist_entry = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
        if blacklist_entry:
            return {"allowed": False, "blacklisted": True}

        # Check for general blacklist subdomain matches
        for entry in db.query(BlacklistEntry).all():
            blacklist_domain = entry.domain.lower()
            if domain.endswith('.' + blacklist_domain):
                return {"allowed": False, "blacklisted": True}

        # Check if domain is in RMM blocked list - block RMM tools by default ONLY if explicitly blacklisted or not explicitly allowed
        is_rmm_blocked = any(domain == rmm_domain or domain.endswith('.' + rmm_domain) for rmm_domain in RMM_BLOCKED_DOMAINS)
        if is_rmm_blocked:
            # RMM domains are blocked by default; do not block if there's an active temporary unblock
            return {"allowed": False, "rmm_blocked": True}

        # Default to allowing other sites
        return {"allowed": True}
    finally:
        db.close()

def build_access_request_response(req):
    return {
        "id": req.id,
        "domain": req.domain,
        "reason": req.reason,
        "requested_duration_minutes": req.requested_duration_minutes,
        "requested_by": req.requested_by,
        "status": req.status,
        "rejection_reason": req.rejection_reason,
        "requested_at": req.requested_at.isoformat() if req.requested_at else None,
        "resolved_at": req.resolved_at.isoformat() if req.resolved_at else None
    }

@app.get("/api/requests")
async def get_access_requests(current_user: User = Depends(get_current_user)):
    """Get access requests for the current user or all requests for admins"""
    db = SessionLocal()
    try:
        if current_user.role.lower() == 'admin':
            requests = db.query(AccessRequest).all()
        else:
            requests = db.query(AccessRequest).filter(AccessRequest.requested_by == current_user.username).all()
        return [build_access_request_response(req) for req in requests]
    finally:
        db.close()

@app.post("/api/requests")
async def create_access_request(request: AccessRequestCreate, current_user: User = Depends(get_current_user)):
    """Create new access request"""
    db = SessionLocal()
    try:
        requested_domain = normalize_domain(request.domain)
        if not requested_domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        # Only allow creating access requests for domains that are currently blocked
        check_result = await check_domain(requested_domain)
        if check_result.get("allowed", True):
            raise HTTPException(status_code=400, detail="Domain is not blocked and does not need an access request")

        existing = db.query(AccessRequest).filter(
            AccessRequest.domain == requested_domain,
            AccessRequest.status == "pending"
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Request for this domain already exists")

        req = AccessRequest(
            domain=requested_domain,
            reason=request.reason,
            requested_duration_minutes=request.requested_duration_minutes,
            requested_by=current_user.username
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        create_notification(db, target_role='admin', type='ACCESS_REQUEST_SUBMITTED', title='New access request', message=f'{current_user.username} requested access to {requested_domain}', severity='info', metadata={'domain': requested_domain, 'requested_by': current_user.username})
        log_audit(db, current_user.username, 'create_access_request', target=requested_domain, result='pending')
        return {"status": "created", "id": req.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.get("/public/requests")
async def get_public_access_requests(domain: Optional[str] = None):
    db = SessionLocal()
    try:
        query = db.query(AccessRequest)
        if domain:
            normalized_domain = normalize_domain(domain)
            query = query.filter(AccessRequest.domain == normalized_domain)
        requests = query.order_by(AccessRequest.requested_at.desc()).all()
        return [build_access_request_response(req) for req in requests]
    finally:
        db.close()

@app.post("/public/requests")
async def create_public_access_request(request: AccessRequestCreate):
    db = SessionLocal()
    try:
        requested_domain = normalize_domain(request.domain)
        if not requested_domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        check_result = await check_domain(requested_domain)
        if check_result.get("allowed", True):
            raise HTTPException(status_code=400, detail="Domain is not blocked and does not need an access request")

        existing = db.query(AccessRequest).filter(
            AccessRequest.domain == requested_domain,
            AccessRequest.status == "pending"
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Request for this domain already exists")

        req = AccessRequest(
            domain=requested_domain,
            reason=request.reason,
            requested_duration_minutes=request.requested_duration_minutes,
            requested_by='public'
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        create_notification(db, target_role='admin', type='ACCESS_REQUEST_SUBMITTED', title='New access request', message=f'Public request for {requested_domain} submitted', severity='info', metadata={'domain': requested_domain, 'requested_by': 'public'})
        log_audit(db, 'public', 'create_access_request', target=requested_domain, result='pending')
        return {"status": "created", "id": req.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.post("/api/requests/{request_id}/approve")
async def approve_access_request(request_id: int, payload: AccessRequestApprove, current_user: User = Depends(get_current_admin)):
    """Approve access request"""
    db = SessionLocal()
    try:
        req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
        if req.status != "pending":
            raise HTTPException(status_code=400, detail="Request is not pending")

        expires_at = None
        if payload.duration_hours is not None and payload.duration_hours > 0:
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=payload.duration_hours)

        # Create a temporary unblock record so the blacklisted domain is allowed for the duration
        temp = TemporaryUnblock(
            domain=req.domain,
            expires_at=expires_at,
            added_by=current_user.username
        )
        db.add(temp)

        # If the domain exists in the explicit DB blacklist, remove it now (treat as manual unblock)
        try:
            black_entry = db.query(BlacklistEntry).filter(BlacklistEntry.domain == req.domain).first()
            if black_entry:
                db.delete(black_entry)
                create_notification(db, target_role='admin', type='DOMAIN_TEMPORARILY_UNBLOCKED', title='Domain temporarily unblocked', message=f'{req.domain} was temporarily unblocked by {current_user.username}', severity='info', metadata={'domain': req.domain, 'expires_at': format_iso_utc(expires_at)})
        except Exception:
            pass

        req.status = "approved"
        req.resolved_at = datetime.datetime.utcnow()

        db.commit()
        create_notification(db, target_role='user', target_user=req.requested_by, type='ACCESS_REQUEST_APPROVED', title='Access request approved', message=f'Your request for {req.domain} was approved', severity='success', metadata={'domain': req.domain, 'duration_hours': payload.duration_hours})
        log_audit(db, current_user.username, 'approve_access_request', target=req.domain, result='approved')
        return {"status": "approved", "domain": req.domain}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.post("/api/requests/{request_id}/reject")
async def reject_access_request(request_id: int, payload: AccessRequestReject, current_user: User = Depends(get_current_admin)):
    """Reject access request"""
    db = SessionLocal()
    try:
        req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
        if req.status != "pending":
            raise HTTPException(status_code=400, detail="Request is not pending")

        req.status = "rejected"
        req.rejection_reason = payload.rejection_reason
        req.resolved_at = datetime.datetime.utcnow()

        db.commit()
        create_notification(db, target_role='user', target_user=req.requested_by, type='ACCESS_REQUEST_REJECTED', title='Access request rejected', message=f'Your request for {req.domain} was rejected: {payload.rejection_reason}', severity='danger', metadata={'domain': req.domain, 'reason': payload.rejection_reason})
        log_audit(db, current_user.username, 'reject_access_request', target=req.domain, result='rejected')
        return {"status": "rejected"}
    finally:
        db.close()


@app.post("/admin/decline_request/{request_id}")
async def admin_decline_access_request(request_id: int, reason: Optional[str] = None, current_user: User = Depends(get_current_admin)):
    """Admin convenience endpoint to decline an access request (compatibility)."""
    db = SessionLocal()
    try:
        req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
        if req.status != 'pending':
            raise HTTPException(status_code=400, detail='Request is not pending')

        req.status = 'rejected'
        req.rejection_reason = reason or 'Declined by admin'
        req.resolved_at = datetime.datetime.utcnow()
        db.commit()
        create_notification(db, target_role='user', target_user=req.requested_by, type='ACCESS_REQUEST_REJECTED', title='Access request rejected', message=f'Your request for {req.domain} was rejected: {req.rejection_reason}', severity='danger', metadata={'domain': req.domain, 'reason': req.rejection_reason})
        log_audit(db, current_user.username, 'admin_decline_access_request', target=req.domain, result='rejected')
        return {'status': 'rejected'}
    finally:
        db.close()

@app.get("/api/status")
async def get_status():
    """Get system status"""
    db = SessionLocal()
    try:
        total_temporary_unblocks = db.query(TemporaryUnblock).count()
        pending_requests = db.query(AccessRequest).filter(AccessRequest.status == "pending").count()

        # Check proxy status (simplified - in real implementation would check if mitmproxy is running)
        proxy_running = True  # Placeholder
        uptime_hours = int((datetime.datetime.utcnow() - START_TIME).total_seconds() // 3600)

        return {
            "proxy_running": proxy_running,
            "backend_running": True,
            "blocked_domains": len(RMM_BLOCKED_DOMAINS),
            "temporary_unblocks": total_temporary_unblocks,
            "whitelisted_domains": total_temporary_unblocks,
            "pending_requests": pending_requests,
            "uptime_hours": uptime_hours
        }
    finally:
        db.close()


def scan_file_path(path: str) -> Optional[Dict[str, Any]]:
    steps: List[Dict[str, str]] = []
    normalized_name = normalize_signature(os.path.basename(path))
    steps.append({"step": "extract_signature", "detail": f"Normalized filename to signature: {normalized_name}"})
    file_hash = None
    file_content = ''
    # Stream file for hashing to avoid loading very large files into memory
    if os.path.isfile(path):
        try:
            import hashlib as _hashlib
            hasher = _hashlib.sha256()
            size = os.path.getsize(path)
            text_extensions = {'.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.js', '.css', '.py', '.md', '.ini', '.cfg', '.yaml', '.yml', '.bat', '.ps1', '.sh', '.c', '.cpp', '.h', '.asm'}
            is_text_file = os.path.splitext(path)[1].lower() in text_extensions
            max_content_scan = 512 * 1024 if is_text_file and size <= 2 * 1024 * 1024 else 0
            read_bytes = 0
            buffer_chunks = []
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    if max_content_scan and read_bytes < max_content_scan:
                        need = max_content_scan - read_bytes
                        buffer_chunks.append(chunk[:need])
                        read_bytes += len(chunk[:need])
            file_hash = hasher.hexdigest()
            steps.append({"step": "extract_signature", "detail": f"Computed SHA256 hash: {file_hash}"})
            if buffer_chunks:
                content_bytes = b''.join(buffer_chunks)
                try:
                    file_content = content_bytes.decode('utf-8', errors='ignore').lower()
                    steps.append({"step": "extract_signature", "detail": "Loaded text content for pattern comparison."})
                except Exception:
                    steps.append({"step": "extract_signature", "detail": "Could not decode content for additional pattern matching."})
            else:
                steps.append({"step": "extract_signature", "detail": "Skipping raw content scanning for binary/large file; using filename and hash matching only."})
        except Exception as exc:
            steps.append({"step": "extract_signature", "detail": f"Failed to read file signature: {exc}"})
    matches = []

    steps.append({"step": "compare_signature", "detail": "Comparing extracted values against known signatures."})
    try:
        for entry in signature_db:
            # Defensive: ensure entry is a dict-like object
            if not isinstance(entry, dict):
                continue
            pattern_raw = entry.get('pattern', '')
            pattern = normalize_signature(pattern_raw)
            if not pattern:
                continue
            entry_id = (entry.get('id') or '')
            # Fast-path for hash entries
            if isinstance(entry_id, str) and entry_id.startswith('hash') and file_hash:
                if file_hash == pattern or file_hash.startswith(pattern) or pattern.startswith(file_hash):
                    matches.append(entry)
                    continue

            candidates = []
            if file_content:
                candidates.append(file_content)
            candidates.append(normalized_name)

            matched = False
            for candidate in candidates:
                try:
                    if calculate_signature_match_score(candidate, entry) >= 0.75:
                        matched = True
                        break
                except Exception:
                    # Skip this candidate/entry if comparison fails
                    continue
            if matched:
                matches.append(entry)
                continue
    except Exception as exc:
        steps.append({"step": "compare_signature", "detail": f"Signature comparison failed: {exc}"})

    if matches:
        steps.append({"step": "result", "detail": f"Found {len(matches)} matching signature(s)."})
        return {
            "path": path,
            "matches": [{"id": entry.get('id'), "pattern": entry.get('pattern'), "description": entry.get('description')} for entry in matches],
            "steps": steps
        }

    steps.append({"step": "result", "detail": "No signatures matched this file."})
    return {"path": path, "matches": [], "steps": steps}

@app.post("/compare_signature")
async def compare_signature(request: SignatureCompareRequest):
    try:
        if not signature_db:
            raise RuntimeError("Signature database is not loaded or is empty.")

        best_match = None
        best_score = 0.0
        for entry in signature_db:
            score = calculate_signature_match_score(request.signature, entry)
            if score > best_score:
                best_score = score
                best_match = entry

        if best_match is None:
            return {
                "matched": False,
                "score": 0.0,
                "details": "No known signatures found to compare against."
            }

        return {
            "matched": best_score >= 0.75,
            "score": round(best_score, 4),
            "match_id": best_match.get("id"),
            "match_description": best_match.get("description"),
            "known_pattern": best_match.get("pattern")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

RMM_BLOCKED_DOMAINS = [
    "anydesk.com",
    "teamviewer.com",
    "logmein.com",
    "splashtop.com",
    "ultravnc.com",
    "tightvnc.com",
    "parsec.app",
    "remoteutilities.com",
    "ammyy.com",
    "connectwise.com",
    "screenconnect.com",
    "beyondtrust.com",
    "kaseya.com"
]

@app.post("/dns_lookup")
async def dns_lookup(request: DNSLookupRequest):
    domain = request.domain.strip().lower()
    blocked = any(domain == blocked_domain or domain.endswith('.' + blocked_domain) for blocked_domain in RMM_BLOCKED_DOMAINS)
    blocked_page_url = "http://127.0.0.1:8000/blocked"
    if blocked:
        return {
            "ip": "127.0.0.1",
            "blocked": True,
            "blocked_domains": RMM_BLOCKED_DOMAINS,
            "warning_page_url": blocked_page_url,
            "message": "This domain is blocked by ShieldGuard DNS filtering. Open the warning page for more details."
        }
    return {
        "ip": "8.8.8.8",
        "blocked": False,
        "blocked_domains": RMM_BLOCKED_DOMAINS,
        "warning_page_url": blocked_page_url,
        "message": "This domain is not blocked by ShieldGuard DNS filtering."
    }

# Placeholder for DNS related endpoints


# Admin endpoints
@app.get("/admin/requests")
async def get_requests(current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        requests = db.query(WhitelistRequest).filter(WhitelistRequest.approved == False).all()
        return [{"id": r.id, "domain": r.domain, "user_id": r.user_id, "requested_at": r.requested_at} for r in requests]
    finally:
        db.close()

@app.post("/admin/approve/{request_id}")
async def approve_request(request_id: int, payload: ApproveRequestPayload, current_user: User = Depends(get_current_admin)):
    db = SessionLocal()
    try:
        request = db.query(WhitelistRequest).filter(WhitelistRequest.id == request_id).first()
        if not request:
            raise HTTPException(status_code=404, detail="Request not found")
        request.approved = True
        request.approved_at = datetime.datetime.utcnow()
        request.expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=payload.duration_hours)
        db.commit()
        return {"status": "approved"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@app.get("/blocked")
async def blocked_page():
    static_dir = Path(__file__).parent / 'static'
    page_path = static_dir / 'blocked.html'
    if not page_path.exists():
        raise HTTPException(status_code=404, detail='Blocked page not found')
    return Response(content=page_path.read_bytes(), media_type='text/html')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)