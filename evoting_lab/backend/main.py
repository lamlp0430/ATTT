from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import os
import hashlib
import bcrypt
import jwt
import logging
from datetime import datetime, timedelta
import pathlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# --- LOGGING ---
logging.basicConfig(filename='evoting_security.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="E-Voting Lab UTH - Full Security")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET", "fallback_secret_if_env_fails")
ALGORITHM = "HS256"
REVOKED_TOKENS = set()
login_attempts = {}

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "evoting"),
        user=os.getenv("DB_USER", "admin"),
        password=os.getenv("DB_PASS", "secretpassword")
    )

# --- MODELS ---
class CandidateCreate(BaseModel):
    name: str
    party: str = "Độc lập"
    image_url: str = ""
    dob: str = ""
    position: str = ""
    education: str = ""
    details: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class VoteRequest(BaseModel):
    candidate_id: int

class ScheduleRequest(BaseModel):
    start_time: str
    end_time: str

# --- CRYPTOGRAPHY (RSA) ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_priv.decode('utf-8'), pem_pub.decode('utf-8')

# --- BCRYPT & JWT & DEP ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc bị thiếu!")
    token = authorization.split(" ")[1]

    if token in REVOKED_TOKENS:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã bị thu hồi!")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM revoked_tokens WHERE token = %s", (token,))
    if cur.fetchone():
        REVOKED_TOKENS.add(token)
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã bị thu hồi!")
    cur.close()
    conn.close()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        payload["token"] = token
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn!")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ!")

# --- API ENDPOINTS ---

@app.post("/login")
def login(req: Request, data: LoginRequest):
    client_ip = req.client.host
    now = datetime.now()

    if client_ip in login_attempts:
        attempts, lockout = login_attempts[client_ip]
        if lockout and now < lockout:
            logger.warning(f"Brute-force attempt from {client_ip}")
            raise HTTPException(status_code=429, detail="Đang bị khóa 5 phút do sai quá nhiều!")
        elif lockout and now >= lockout:
            login_attempts[client_ip] = [0, None]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, role, rsa_private_key FROM users WHERE username = %s", (data.username,))
    user = cur.fetchone()

    if not user or not verify_password(data.password, user[2]):
        attempts = login_attempts.get(client_ip, [0, None])[0] + 1
        lockout = now + timedelta(minutes=5) if attempts >= 5 else None
        login_attempts[client_ip] = [attempts, lockout]
        logger.warning(f"Login failed for {data.username} from {client_ip}")
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Tài khoản hoặc mật khẩu không chính xác!")

    if not user[4]:
        priv, pub = generate_rsa_keys()
        cur.execute("UPDATE users SET rsa_private_key=%s, rsa_public_key=%s WHERE username=%s", (priv, pub, data.username))
        conn.commit()
    cur.close()
    conn.close()

    login_attempts[client_ip] = [0, None]
    logger.info(f"User {data.username} logged in successfully.")

    payload = {"sub": user[1], "role": user[3], "exp": datetime.utcnow() + timedelta(minutes=10)}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "role": user[3]}

@app.get("/candidates")
def get_candidates():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, party, image_url, TO_CHAR(dob, 'DD/MM/YYYY'), position, education, details FROM candidates ORDER BY id ASC")
    res = []
    for r in cur.fetchall():
        res.append({
            "id": r[0], "name": r[1], "party": r[2],
            "image_url": r[3], "dob": r[4], "position": r[5],
            "education": r[6], "details": r[7]
        })
    cur.close()
    conn.close()
    return res

@app.post("/candidates")
def add_candidate(req: CandidateCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Admin mới có quyền thêm ứng viên!")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        dob_val = req.dob if req.dob else None
        cur.execute(
            "INSERT INTO candidates (name, party, image_url, dob, position, education, details) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (req.name, req.party, req.image_url, dob_val, req.position, req.education, req.details)
        )
        conn.commit()
        logger.info(f"Admin {current_user['sub']} added a new candidate: {req.name}")
        return {"message": f"Đã thêm ứng viên {req.name} thành công!"}
    except Exception:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Lỗi hệ thống khi thêm ứng viên!")
    finally:
        cur.close()
        conn.close()


# 1. Thêm Pydantic Model cho việc chỉnh sửa ứng viên (nếu chưa có hoặc gom chung)
class UpdateCandidateRequest(BaseModel):
    name: str
    party: str = "Độc lập"
    image_url: str = ""
    dob: str = ""
    position: str = ""
    education: str = ""
    details: str = ""


# 2. Thêm Endpoint chỉnh sửa thông tin ứng viên
@app.put("/candidates/{candidate_id}")
def update_candidate(candidate_id: int, req: UpdateCandidateRequest, current_user: dict = Depends(get_current_user)):
    # Phân quyền: Chỉ ADMIN mới có quyền chỉnh sửa ứng viên
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Admin mới có quyền chỉnh sửa ứng viên!")

    if not req.name:
        raise HTTPException(status_code=400, detail="Tên ứng viên không được để trống!")

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Kiểm tra xem ứng viên có tồn tại hay không
        cur.execute("SELECT id FROM candidates WHERE id = %s", (candidate_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Không tìm thấy ứng viên cần chỉnh sửa!")

        # Thực hiện cập nhật thông tin ứng viên
        query = """
            UPDATE candidates 
            SET name = %s, party = %s, image_url = %s, dob = %s, position = %s, education = %s, details = %s
            WHERE id = %s
        """
        cur.execute(query, (req.name, req.party, req.image_url, req.dob, req.position, req.education, req.details,
                            candidate_id))
        conn.commit()

        cur.close()
        conn.close()

        # Ghi log bảo mật (NFR-09)
        logger.info(f"Admin {current_user.get('username')} đã chỉnh sửa ứng viên ID: {candidate_id}")

        return {"message": f"Cập nhật thông tin ứng viên '{req.name}' thành công!"}

    except Exception as e:
        logger.error(f"Lỗi khi chỉnh sửa ứng viên: {str(e)}")
        raise HTTPException(status_code=500, detail="Lỗi kết nối hoặc xử lý phía máy chủ!")

@app.get("/results")
def get_results():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.name, COUNT(v.id) 
        FROM candidates c 
        LEFT JOIN votes v ON c.id = v.candidate_id 
        GROUP BY c.name ORDER BY COUNT(v.id) DESC
    """)
    res = [{"name": r[0], "votes": r[1]} for r in cur.fetchall()]
    cur.close()
    conn.close()
    return res

@app.get("/receipt/{receipt_hash}")
def verify_receipt(receipt_hash: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT candidate_id FROM votes WHERE vote_hash = %s", (receipt_hash,))
    vote = cur.fetchone()
    cur.close()
    conn.close()
    if vote:
        return {"status": "Tồn tại", "message": "Phiếu bầu của bạn đã được ghi nhận trên chuỗi an toàn."}
    raise HTTPException(status_code=404, detail="Không tìm thấy phiếu bầu hợp lệ.")

@app.post("/election/toggle")
def toggle_election(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Admin mới có quyền này!")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM election_status WHERE id=1")
    current_status = cur.fetchone()[0]
    new_status = not current_status
    cur.execute("UPDATE election_status SET is_active=%s WHERE id=1", (new_status,))
    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"Admin toggled election status to {new_status}")
    return {"message": f"Bầu cử đã {'BẬT' if new_status else 'TẮT'} thành công."}


@app.get("/election/status")
def get_election_status():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active, start_time, end_time FROM election_status WHERE id=1")
    status = cur.fetchone()
    cur.close()
    conn.close()

    return {
        "is_active": status[0],
        "start_time": status[1].isoformat() if status[1] else None,
        "end_time": status[2].isoformat() if status[2] else None
    }

@app.post("/vote")
def vote(req: VoteRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "voter":
        raise HTTPException(status_code=403, detail="Chỉ cử tri mới được bỏ phiếu!")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT is_active, start_time, end_time FROM election_status WHERE id=1")
    status = cur.fetchone()

    if not status[0]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Hòm phiếu đang bị KHÓA THỦ CÔNG bởi Admin!")

    now = datetime.now()
    if status[1] and now < status[1]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail=f"Chưa đến giờ! Hòm phiếu mở lúc: {status[1].strftime('%d/%m/%Y %H:%M')}")

    if status[2] and now > status[2]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Bầu cử ĐÃ KẾT THÚC, hòm phiếu đã đóng!")

    cur.execute("SELECT has_voted FROM users WHERE username = %s", (current_user["sub"],))
    if cur.fetchone()[0]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Bạn đã bỏ phiếu rồi, không thể bầu lại!")

    cur.execute("SELECT rsa_private_key FROM users WHERE username = %s", (current_user["sub"],))
    user_private_key_pem = cur.fetchone()[0]

    private_key = serialization.load_pem_private_key(user_private_key_pem.encode('utf-8'), password=None)
    voter_hash = hashlib.sha256((current_user["sub"] + SECRET_KEY).encode('utf-8')).hexdigest()

    cur.execute("SELECT vote_hash FROM votes ORDER BY id DESC LIMIT 1")
    last_vote = cur.fetchone()
    previous_hash = last_vote[0] if last_vote else "GENESIS_HASH"

    vote_data = f"{voter_hash}-{req.candidate_id}-{previous_hash}"

    signature = private_key.sign(
        vote_data.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    signature_hex = signature.hex()

    raw_block = f"{vote_data}-{signature_hex}-{SECRET_KEY}"
    vote_hash = hashlib.sha256(raw_block.encode('utf-8')).hexdigest()

    cur.execute(
        "INSERT INTO votes (voter_hash, candidate_id, previous_hash, vote_hash, rsa_signature) VALUES (%s, %s, %s, %s, %s)",
        (voter_hash, req.candidate_id, previous_hash, vote_hash, signature_hex)
    )
    cur.execute("UPDATE users SET has_voted = TRUE WHERE username = %s", (current_user["sub"],))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "message": "Bỏ phiếu thành công! Lá phiếu đã được ký số RSA an toàn.",
        "receipt": vote_hash
    }

@app.get("/audit_votes")
def audit_votes(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "auditor":
        raise HTTPException(status_code=403, detail="Chỉ Kiểm toán viên mới có quyền thực hiện!")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, voter_hash, candidate_id, previous_hash, vote_hash, rsa_signature FROM votes ORDER BY id ASC")
    rows = cur.fetchall()

    cur.execute("SELECT username, rsa_public_key FROM users")
    user_keys = cur.fetchall()
    cur.close()
    conn.close()

    hash_to_pubkey = {}
    for uname, pubkey in user_keys:
        uhash = hashlib.sha256((uname + SECRET_KEY).encode('utf-8')).hexdigest()
        hash_to_pubkey[uhash] = pubkey

    expected_prev = "GENESIS_HASH"
    for row in rows:
        v_id, v_hash, c_id, p_hash_saved, v_hash_saved, sig_saved = row

        if p_hash_saved != expected_prev:
            return {"status": "DANGER", "message": f"Gian lận: Đứt chuỗi liên kết khối tại ID {v_id}!"}

        vote_data = f"{v_hash}-{c_id}-{p_hash_saved}"
        pubkey_pem = hash_to_pubkey.get(v_hash)
        if not pubkey_pem:
            return {"status": "DANGER", "message": f"Gian lận: Không tìm thấy Khóa công khai hợp lệ cho phiếu ID {v_id}!"}

        try:
            public_key = serialization.load_pem_public_key(pubkey_pem.encode('utf-8'))
            public_key.verify(
                bytes.fromhex(sig_saved),
                vote_data.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception:
            return {"status": "DANGER", "message": f"Gian lận: Chữ ký số RSA tại phiếu ID {v_id} không hợp lệ!"}

        raw_block = f"{vote_data}-{sig_saved}-{SECRET_KEY}"
        if hashlib.sha256(raw_block.encode('utf-8')).hexdigest() != v_hash_saved:
            return {"status": "DANGER", "message": f"Gian lận: Mã băm khối tại ID {v_id} đã bị thay đổi!"}

        expected_prev = v_hash_saved

    return {"status": "SAFE", "message": "Hòm phiếu an toàn tuyệt đối 100%. Đã xác thực toàn vẹn Blockchain & Chữ ký số cử tri!"}

@app.post("/logout")
def logout_endpoint(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token không hợp lệ!")
    token = authorization.split(" ")[1]
    REVOKED_TOKENS.add(token)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO revoked_tokens (token) VALUES (%s) ON CONFLICT DO NOTHING", (token,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Lỗi đồng bộ Token Blacklist vào DB: {str(e)}")
    return {"message": "Đăng xuất thành công!"}

@app.post("/reset_system")
def reset_system(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Cấm truy cập!")
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("TRUNCATE TABLE votes RESTART IDENTITY CASCADE;")
        cur.execute("UPDATE users SET has_voted = FALSE;")
        conn.commit()
        logger.warning(f"Admin {current_user['sub']} reset system.")
        return {"message": "Đã dọn dẹp Hòm phiếu và Khôi phục hệ thống về trạng thái ban đầu."}
    finally:
        cur.close()
        conn.close()

@app.post("/election/schedule")
def schedule_election(req: ScheduleRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Chỉ Admin mới có quyền đổi lịch!")
    try:
        st = datetime.fromisoformat(req.start_time)
        et = datetime.fromisoformat(req.end_time)
    except ValueError:
        raise HTTPException(status_code=400, detail="Sai định dạng thời gian!")

    if st >= et:
        raise HTTPException(status_code=400, detail="Thời gian kết thúc phải lớn hơn bắt đầu!")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE election_status SET start_time=%s, end_time=%s WHERE id=1", (st, et))
    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"Admin {current_user['sub']} updated schedule: {st} to {et}")
    return {"message": f"Đã cài đặt thời gian bầu cử tự động: Từ {st.strftime('%d/%m/%Y %H:%M')} đến {et.strftime('%d/%m/%Y %H:%M')}"}

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    html_path = pathlib.Path("frontend.html")
    if html_path.exists():
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Lỗi: frontend.html bị thiếu!</h1>"