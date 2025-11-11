# app.py
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
import os, json, uuid, re
from functools import wraps

# ---------------------- Config ----------------------
app = Flask(__name__)
app.secret_key = "dev-change-me"  # troque em produção

DATA_FILE = "data.json"
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}

os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------- Helpers (persistência) ----------------------
def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS


def save_upload(field_name: str, subdir: str = ""):
    """
    Pega arquivo do request.files[field_name], valida e salva.
    Retorna caminho relativo (ex.: 'ein/<uuid>_nome.pdf') ou None.
    """
    file = request.files.get(field_name)
    if not file or file.filename.strip() == "":
        return None

    fname = secure_filename(file.filename)
    if not allowed_file(fname):
        flash(f"Extensão não permitida em {field_name}.", "warning")
        return None

    unique = f"{uuid.uuid4().hex}_{fname}"
    folder = os.path.join(UPLOAD_DIR, subdir) if subdir else UPLOAD_DIR
    os.makedirs(folder, exist_ok=True)

    file_path = os.path.join(folder, unique)
    file.save(file_path)

    # retorna caminho relativo para servir via /uploads/<path>
    rel_dir = subdir.strip("/\\")
    rel_path = os.path.join(rel_dir, unique) if rel_dir else unique
    return rel_path.replace("\\", "/")


def parse_date_yyyy_mm_dd(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


# ---------------------- Helpers (normalização e onboarding) ----------------------
def ensure_profile_defaults(u: dict) -> bool:
    """Garante estrutura mínima em u['profile'] e migra chaves antigas top-level.
    Retorna True se modificou.
    """
    changed = False

    if not isinstance(u.get("profile"), dict):
        u["profile"] = {}
        changed = True

    prof = u["profile"]

    # Migra chaves top-level antigas para dentro de profile
    for key in ("basic", "docs", "terms", "onboarding"):
        if key in u and key != "profile":
            if key == "onboarding" and not isinstance(u[key], dict):
                prof["onboarding"] = {"step1": False, "step2": False, "step3": False}
            else:
                prof[key] = u[key]
            del u[key]
            changed = True

    # Garante as seções
    if "basic" not in prof or not isinstance(prof["basic"], dict):
        prof["basic"] = {}
        changed = True
    if "docs" not in prof or not isinstance(prof["docs"], dict):
        prof["docs"] = {}
        changed = True
    if "terms" not in prof or not isinstance(prof["terms"], dict):
        prof["terms"] = {}
        changed = True
    if "onboarding" not in prof or not isinstance(prof["onboarding"], dict):
        prof["onboarding"] = {"step1": False, "step2": False, "step3": False}
        changed = True
    else:
        ob = prof["onboarding"]
        if "step1" not in ob: ob["step1"] = False; changed = True
        if "step2" not in ob: ob["step2"] = False; changed = True
        if "step3" not in ob: ob["step3"] = False; changed = True

    return changed


def load_data():
    # cria arquivo mínimo se não existir
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump({"users": [], "services": [], "contractors": [], "subcontractors": []}, f)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    # garante chaves mínimas
    data.setdefault("users", [])
    data.setdefault("services", [])
    data.setdefault("contractors", [])
    data.setdefault("subcontractors", [])

    changed = False

    # --------- NORMALIZA PERFIL DOS USUÁRIOS ---------
    for u in data["users"]:
        if ensure_profile_defaults(u):
            changed = True

    # --------- NORMALIZA SERVIÇOS / BIDS ---------
    for s in data["services"]:
        if "id" not in s or not s["id"]:
            s["id"] = str(uuid.uuid4()); changed = True
        if "owner_id" not in s:
            s["owner_id"] = None; changed = True

        # bids -> [{"value": float, "user_id": str|None}]
        if "bids" in s and isinstance(s["bids"], list):
            new_bids = []
            for b in s["bids"]:
                if isinstance(b, dict) and "value" in b:
                    if "user_id" not in b:
                        b["user_id"] = None; changed = True
                    try:
                        b["value"] = float(b["value"])
                    except Exception:
                        continue
                    new_bids.append(b)
                else:
                    try:
                        new_bids.append({"value": float(b), "user_id": None})
                        changed = True
                    except Exception:
                        pass
            s["bids"] = new_bids
        else:
            s["bids"] = []; changed = True

        # winner coerente
        best = min(s["bids"], key=lambda x: x["value"], default=None)
        if best is None:
            if s.get("winner") is not None or s.get("winner_user_id") is not None:
                s["winner"] = None
                s["winner_user_id"] = None
                changed = True
        else:
            w = float(best["value"])
            if s.get("winner") != w or s.get("winner_user_id") != best.get("user_id"):
                s["winner"] = w
                s["winner_user_id"] = best.get("user_id")
                changed = True

    if changed:
        save_data(data)

    return data


def get_user_dict(data, user_id):
    for u in data["users"]:
        if u["id"] == user_id:
            return u
    return None


def compute_onboarding_info(u: dict):
    """Retorna dict com percent, flags e warnings para banner."""
    prof = u.get("profile", {})
    ob = prof.get("onboarding", {})
    step1 = bool(ob.get("step1"))
    step2 = bool(ob.get("step2"))
    step3 = bool(ob.get("step3"))

    done = sum([step1, step2, step3])
    percent = int(round(done * 100 / 3))

    missing = []
    if not step1: missing.append("step1")
    if not step2: missing.append("step2")
    if not step3: missing.append("step3")

    warnings = []
    docs = prof.get("docs", {})
    for key in ("ein_expiry","w9_expiry","coi_expiry"):
        v = docs.get(key)
        if v:
            try:
                d = datetime.strptime(v, "%Y-%m-%d").date()
                if d < date.today():
                    warnings.append(f"{key.split('_')[0].upper()} vencido — atualize o documento.")
            except Exception:
                pass

    if not step2: warnings.append("Complete a Etapa 2 (Documentos).")
    if not step3: warnings.append("Assine a Etapa 3 (Termo de Conduta).")

    return {
        "percent": percent,
        "missing_steps": missing,
        "warnings": warnings,
        "step1": step1,
        "step2": step2,
        "step3": step3,
    }


# ---------------------- PDF utils (extração de validade genérica) ----------------------
def _read_pdf_text(abs_path: str) -> str:
    """Extrai texto do PDF (PyPDF2, se disponível)."""
    text = ""
    try:
        import PyPDF2  # type: ignore
        with open(abs_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                try:
                    t = page.extract_text() or ""
                except Exception:
                    t = ""
                if t:
                    text += "\n" + t
    except Exception:
        return ""
    return text


DATE_PATTERNS = [
    r"\b(20\d{2})-(0?[1-9]|1[0-2])-(0?[1-9]|[12]\d|3[01])\b",            # YYYY-MM-DD
    r"\b(0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])[/-](20\d{2})\b",     # MM/DD/YYYY
    r"\b(0?[1-9]|[12]\d|3[01])[/-](0?[1-9]|1[0-2])[/-](20\d{2})\b",     # DD/MM/YYYY
    r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+(0?[1-9]|[12]\d|3[01]),?\s+(20\d{2})\b",
    r"\b(0?[1-9]|[12]\d|3[01])\s+(January|February|March|April|May|June|July|August|September|October|November|December),?\s+(20\d{2})\b",
]

TRIGGER_WORDS = [
    "expiration", "expires", "expiry", "valid until", "valid thru", "valid through",
    "policy expiration", "exp date", "exp.", "exp ", "validade", "vencimento"
]


def _normalize_date_tuple_to_yyyy_mm_dd(match: re.Match, pattern_index: int) -> str | None:
    try:
        if pattern_index == 0:       # YYYY-MM-DD
            y, m, d = int(match.group(1)), int(match.group(2)), int(match.group(3))
        elif pattern_index == 1:     # MM/DD/YYYY
            m, d, y = int(match.group(1)), int(match.group(2)), int(match.group(3))
        elif pattern_index == 2:     # DD/MM/YYYY
            d, m, y = int(match.group(1)), int(match.group(2)), int(match.group(3))
        elif pattern_index == 3:     # Mon DD, YYYY
            month_map = {
                "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
                "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12
            }
            key = match.group(1).lower()
            key = "sept" if key.startswith("sept") else key[:3]
            m = month_map[key]
            d = int(match.group(2)); y = int(match.group(3))
        else:                        # DD Month YYYY
            d = int(match.group(1))
            month_map = {
                "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
                "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12
            }
            m = month_map[match.group(2).lower()]; y = int(match.group(3))
        return date(y, m, d).strftime("%Y-%m-%d")
    except Exception:
        return None


def detect_expiry_from_pdf(abs_pdf_path: str) -> str | None:
    """Detecta data de validade em PDF e retorna 'YYYY-MM-DD'."""
    text = _read_pdf_text(abs_pdf_path)
    if not text:
        return None

    text_low = text.lower()

    # posições das palavras gatilho
    triggers = []
    for w in TRIGGER_WORDS:
        for m in re.finditer(re.escape(w), text_low):
            triggers.append(m.start())
    triggers.sort()

    # coletar datas
    candidates: list[tuple[int, str]] = []
    for i, pat in enumerate(DATE_PATTERNS):
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            normalized = _normalize_date_tuple_to_yyyy_mm_dd(m, i)
            if normalized:
                candidates.append((m.start(), normalized))

    if not candidates:
        return None

    if triggers:
        # data mais próxima de qualquer trigger
        best, best_dist = None, 10**9
        for pos, dstr in candidates:
            for t in triggers:
                dist = abs(pos - t)
                if dist < best_dist:
                    best, best_dist = dstr, dist
        return best
    else:
        # assume a maior (mais futura)
        return max(candidates, key=lambda t: t[1])[1]


# ---------------------- COI A..E parsing (ACORD) ----------------------
# Dependências: pdfplumber (texto). OCR opcional para PDFs escaneados.
try:
    import pdfplumber  # pip install pdfplumber
except Exception:
    pdfplumber = None

try:
    from pdf2image import convert_from_path  # pip install pdf2image
    import pytesseract  # pip install pytesseract
except Exception:
    convert_from_path = None
    pytesseract = None

_COI_DATE_RE = re.compile(r'\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12][0-9]|3[01])[\/\-](\d{2,4})\b')

# Nome canônico por seção (o que será exibido)
_COI_CANONICAL_LABEL = {
    "A": "COMMERCIAL GENERAL LIABILITY",
    "B": "AUTOMOBILE LIABILITY",
    "C": "WORKERS’ COMPENSATION AND EMPLOYERS’ LIABILITY",
    "D": "UMBRELLA / EXCESS LIABILITY",
    "E": "PROPERTY / INLAND MARINE / EQUIPMENT FLOATER",
}

# Regras por seção: keyword principal, termos que DEVEM aparecer no trecho e termos que NÃO PODEM
_COI_SECTION_RULES = {
    # ------------------ Seção A (General Liability) ------------------
    "A": [
        {"kw": "COMMERCIAL GENERAL LIABILITY"},
        {"kw": "CGL"},
    ],
    # ------------------ Seção B (Auto Liability) ------------------
    "B": [
        {"kw": "AUTOMOBILE LIABILITY"},
        {"kw": "AUTO LIABILITY"},
    ],
    # ------------------ Seção C (Workers' Compensation) - MÁXIMA ESPECIFICIDADE ------------------
    "C": [
        # REGRA 1: Procura pela letra 'C' + WORKERS COMPENSATION (Combinação exclusiva neste bloco)
        {"kw": "C WORKERS COMPENSATION", "require": ["WORKERS"], "forbid": ["UMBRELLA", "EXCESS"]},
        # REGRA 2: Employers' Liability (E.L.) está na mesma linha de data
        {"kw": "E.L. EACH ACCIDENT", "require": ["E.L."], "forbid": ["UMBRELLA", "EXCESS"]},
        # REGRA 3: Workers' Comp Policy Number (Este número é muito próximo da data correta)
        {"kw": "08WECAP4WUK", "require": ["WECAP"], "forbid": ["UMBRELLA", "EXCESS"]}, # Usa o Policy Number real 
    ],
 # ------------------ Seção D (Umbrella/Excess) - SOLUÇÃO FINAL COM FORBID EXCLUSIVO ------------------
    "D": [
        # REGRA 1: Procura por UMBRELLA e LIAB
        # Mas PROIBE o termo 'RETENTION'.
        # Por que? Se a linha D/E está vazia (seu COI), ela tem 'UMBRELLA LIAB' E 'RETENTION'. 
        # A regra será encontrada, mas logo depois falhará por causa do 'RETENTION', impedindo-a de roubar a data de C.
        {"kw": "UMBRELLA LIAB", 
         "require": ["UMBRELLA", "LIAB"], 
         "forbid": ["WORKERS", "WC", "COMPENSATION", "EMPLOYERS'", "RETENTION", "S"]}, 

        # REGRA 2 (Fallback para EXCESS, também proibindo RETENTION/S)
        {"kw": "EXCESS LIAB", 
         "require": ["EXCESS", "LIAB"], 
         "forbid": ["WORKERS", "WC", "COMPENSATION", "EMPLOYERS'", "RETENTION", "S"]},
    ],
    # ------------------ Seção E (Property) ------------------
    "E": [
        {"kw": "PROPERTY"},
        {"kw": "INLAND MARINE"},
    ],
}

def _coi_to_dt(s: str):
    m = re.match(r'(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})', s or "")
    if not m:
        return None
    mm, dd, yyyy = m.groups()
    yyyy = int(yyyy)
    if yyyy < 100:
        yyyy += 2000
    try:
        return datetime(yyyy, int(mm), int(dd))
    except Exception:
        return None

def _coi_extract_text(pdf_path: str) -> str:
    # 1) tenta texto nativo
    if pdfplumber:
        try:
            pages = []
            with pdfplumber.open(pdf_path) as pdf:
                for p in pdf.pages:
                    pages.append(p.extract_text() or "")
            t = "\n".join(pages)
            if t.strip():
                return t
        except Exception:
            pass
    # 2) OCR (opcional)
    if convert_from_path and pytesseract:
        try:
            imgs = convert_from_path(pdf_path, dpi=300)
            return "\n".join(pytesseract.image_to_string(img) for img in imgs)
        except Exception:
            return ""
    return ""

def _coi_nearest_date_after_keyword(
    text: str,
    kw: str,
    window: int = 550,
    require_any: list[str] | None = None,
    forbid_any: list[str] | None = None,
):
    """
    Procura a data mais próxima DEPOIS de uma keyword.
    - require_any: pelo menos um desses termos deve aparecer no trecho
    - forbid_any: nenhum desses termos pode aparecer no trecho
    """
    utext = text.upper()
    idx = utext.find(kw.upper())
    if idx == -1:
        return None
    segment = text[idx: idx + window]
    useg = segment.upper()

    if require_any and not any(r.upper() in useg for r in require_any):
        return None
    if forbid_any and any(f.upper() in useg for f in forbid_any):
        return None

    # coleta datas no trecho
    found = [m.group(0) for m in _COI_DATE_RE.finditer(segment)]
    dts = [_coi_to_dt(s) for s in found if s]
    dts = [d for d in dts if d]
    if not dts:
        return None

    # Heurística ACORD: a expiração geralmente é a 2ª data exibida na linha
    return dts[1] if len(dts) >= 2 else dts[0]

def parse_coi_expirations(pdf_path: str):
    """
    Retorna: {"A": {"label": CANONICAL, "expires_at": datetime, "expires_at_str": "MM/DD/YYYY"}, ...}
    Usa regras com require/forbid p/ reduzir falsos-positivos (D vs C).
    """
    text = _coi_extract_text(pdf_path)
    results = {}
    for letter, rules in _COI_SECTION_RULES.items():
        exp_dt = None
        for rule in rules:
            kw = rule["kw"]
            req = rule.get("require") or None
            fbd = rule.get("forbid") or None
            d = _coi_nearest_date_after_keyword(text, kw, window=550, require_any=req, forbid_any=fbd)
            if d:
                exp_dt = d
                break  # primeira boa correspondência para a seção
        if exp_dt:
            results[letter] = {
                "label": _COI_CANONICAL_LABEL.get(letter, "Unknown"),
                "expires_at": exp_dt,
                "expires_at_str": exp_dt.strftime("%m/%d/%Y"),
            }
    return results

def analyze_coi_expirations(exp_map: dict):
    """Ordena e calcula days_left por seção."""
    today = datetime.today()
    items = []
    for k, v in exp_map.items():
        d = v.get("expires_at")
        if d:
            delta = (d - today).days
            items.append((k, d, delta, v.get("label", "")))
    items.sort(key=lambda x: x[1])
    nearest = items[0] if items else None
    return {"ordered": items, "nearest": nearest}


# ---------------------- COI: níveis de alerta e cores ----------------------
def coi_alert_level(days_left: int):
    """
    Retorna (categoria_bootstrap, nivel_texto) de acordo com as faixas:
      60, 45, 30, 15, 5 e 0 dias
    """
    if days_left <= 0:
        return ("danger", "VENCIDO (0d)")
    if days_left <= 5:
        return ("danger", "≤5d")
    if days_left <= 15:
        return ("warning", "≤15d")
    if days_left <= 30:
        return ("warning", "≤30d")
    if days_left <= 45:
        return ("info", "≤45d")
    if days_left <= 60:
        return ("primary", "≤60d")
    return ("success", f"{days_left}d")


# ---------------------- Expiração: helpers genéricos ----------------------
def parse_date_str(s: str) -> date | None:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def expiry_state(date_str: str | None, soon_days: int = 30):
    """
    classifica validade: none | expired | warn | ok (para visão geral do admin)
    """
    if not date_str:
        return {"state": "none", "days": None, "label": "—"}
    d = parse_date_str(date_str)
    if not d:
        return {"state": "none", "days": None, "label": date_str}

    today = date.today()
    delta = (d - today).days
    if d < today:
        return {"state": "expired", "days": delta, "label": f"Vencido há {abs(delta)}d"}
    if delta <= soon_days:
        return {"state": "warn", "days": delta, "label": f"Vence em {delta}d"}
    return {"state": "ok", "days": delta, "label": f"Válido • {d.strftime('%Y-%m-%d')}"}


# ---------------------- User model (JSON) ----------------------
class User(UserMixin):
    def __init__(self, id, email, name, role, status, password_hash, profile=None, **_):
        self.id = id
        self.email = email
        self.name = name
        self.role = role        # 'admin' | 'contractor' | 'subcontractor'
        self.status = status    # 'pending' | 'approved'
        self.password_hash = password_hash
        self.profile = profile or {}

    @staticmethod
    def get(user_id):
        data = load_data()
        for u in data["users"]:
            if u["id"] == user_id:
                return User(**u)
        return None

    @staticmethod
    def get_by_email(email):
        data = load_data()
        for u in data["users"]:
            if u["email"].lower() == email.lower():
                return User(**u)
        return None


# ---------------------- Flask-Login setup ----------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def create_default_admin_if_missing():
    data = load_data()
    has_admin = any(u["role"] == "admin" for u in data["users"])
    if not has_admin:
        admin = {
            "id": str(uuid.uuid4()),
            "email": "admin@example.com",
            "name": "Admin",
            "role": "admin",
            "status": "approved",
            "password_hash": generate_password_hash("admin123"),
            "profile": {
                "basic": {}, "docs": {}, "terms": {},
                "onboarding": {"step1": True, "step2": True, "step3": True}
            }
        }
        data["users"].append(admin)
        save_data(data)
        print(">> Admin criado: admin@example.com / admin123 (troque depois)")


# ---------------------- Acesso por papel ----------------------
def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                flash("Acesso negado para seu perfil.", "warning")
                return redirect(url_for("index"))
            if current_user.role != "admin" and current_user.status != "approved":
                flash("Seu cadastro aguarda aprovação do Admin.", "info")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------- Rotas públicas ----------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------- Auth ----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = User.get_by_email(email)
        if not user or not check_password_hash(user.password_hash, password):
            flash("Credenciais inválidas.", "danger")
            return redirect(url_for("login"))
        login_user(user)
        flash(f"Bem-vindo(a), {user.name}!", "success")
        if user.role == "admin":
            return redirect(url_for("admin"))
        elif user.role == "contractor":
            return redirect(url_for("contractor"))
        else:
            return redirect(url_for("subcontractor"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("index"))


@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in ("contractor", "subcontractor", "admin"):
        flash("Papel inválido.", "danger")
        return redirect(url_for("index"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("Preencha todos os campos.", "warning")
            return redirect(url_for("register", role=role))
        if User.get_by_email(email):
            flash("E-mail já cadastrado.", "warning")
            return redirect(url_for("register", role=role))

        data = load_data()
        status = "approved" if role == "admin" else "pending"
        data["users"].append({
            "id": str(uuid.uuid4()),
            "email": email,
            "name": name,
            "role": role,
            "status": status,
            "password_hash": generate_password_hash(password),
            "profile": {
                "basic": {}, "docs": {}, "terms": {},
                "onboarding": {"step1": False, "step2": False, "step3": False}
            }
        })
        save_data(data)
        if role == "admin":
            flash("Admin criado com sucesso. Faça login.", "success")
        else:
            flash("Cadastro enviado. Aguarde aprovação do Admin.", "info")
        return redirect(url_for("login"))

    return render_template("register.html", role=role)


# ---------------------- CONTRACTOR (home + publicar serviço) ----------------------
@app.route("/contractor", methods=["GET", "POST"])
@login_required
@role_required("contractor", "admin")
def contractor():
    data = load_data()

    if request.method == "POST":
        service = {
            "id": str(uuid.uuid4()),
            "title": request.form["title"],
            "description": request.form["description"],
            "category": request.form["category"],
            "location": request.form["location"],
            "price_range": request.form["price_range"],
            "bids": [],
            "winner": None,
            "winner_user_id": None,
            "owner_id": current_user.id
        }
        data["services"].append(service)
        save_data(data)
        flash("Serviço publicado!", "success")
        return redirect(url_for("contractor"))

    services = data["services"] if current_user.role == "admin" else [
        s for s in data["services"] if s.get("owner_id") == current_user.id
    ]

    u = get_user_dict(data, current_user.id)
    onboarding = compute_onboarding_info(u)

    return render_template("contractor.html", services=services, onboarding=onboarding)


# --------- Contractor: Etapa 1 (dados básicos) ---------
@app.route("/contractor/step1", methods=["GET", "POST"])
@login_required
@role_required("contractor", "admin")
def contractor_step1():
    data = load_data()
    u = get_user_dict(data, current_user.id)

    if request.method == "POST":
        basic = u["profile"]["basic"]
        basic["company_name"] = request.form.get("company_name", "").strip()
        basic["address"] = request.form.get("address", "").strip()
        basic["contact_name"] = request.form.get("contact_name", "").strip()
        basic["contact_phone"] = request.form.get("contact_phone", "").strip()
        basic["founded_year"] = request.form.get("founded_year", "").strip()
        basic["employees"] = request.form.get("employees", "").strip()
        basic["email"] = request.form.get("email", "").strip()
        basic["website"] = request.form.get("website", "").strip()
        basic["facebook"] = request.form.get("facebook", "").strip()
        basic["instagram"] = request.form.get("instagram", "").strip()
        basic["areas"] = request.form.get("areas", "").strip()
        basic["portfolio"] = request.form.get("portfolio", "").strip()
        basic["intro"] = request.form.get("intro", "").strip()
        basic["licenses"] = request.form.get("licenses", "").strip()
        basic["reviews"] = request.form.get("reviews", "").strip()

        u["profile"]["onboarding"]["step1"] = bool(
            basic.get("company_name") and basic.get("contact_name") and basic.get("contact_phone")
        )

        save_data(data)
        flash("Etapa 1 salva.", "success")
        return redirect(url_for("contractor"))

    return render_template("contractor_step1.html", basic=u["profile"]["basic"], user=u)


# --------- Contractor: Etapa 2 (documentos) + COI A..E com alertas por cor ---------
@app.route("/contractor/step2", methods=["GET", "POST"])
@login_required
@role_required("contractor", "admin")
def contractor_step2():
    data = load_data()
    u = get_user_dict(data, current_user.id)
    docs = u["profile"]["docs"]

    if request.method == "POST":
        ein_path = save_upload("ein_file", "ein") or docs.get("ein_path")
        w9_path = save_upload("w9_file", "w9") or docs.get("w9_path")
        coi_path = save_upload("coi_file", "coi") or docs.get("coi_path")

        if ein_path:
            docs["ein_path"] = ein_path
            if ein_path.lower().endswith(".pdf"):
                expiry = detect_expiry_from_pdf(os.path.join(UPLOAD_DIR, ein_path))
                if expiry:
                    docs["ein_expiry"] = expiry

        if w9_path:
            docs["w9_path"] = w9_path
            if w9_path.lower().endswith(".pdf"):
                expiry = detect_expiry_from_pdf(os.path.join(UPLOAD_DIR, w9_path))
                if expiry:
                    docs["w9_expiry"] = expiry

        if coi_path:
            docs["coi_path"] = coi_path
            abs_coi = os.path.join(UPLOAD_DIR, coi_path)

            # 1) Extrair expiração por seção (A..E) e avisar por faixas/cores
            if coi_path.lower().endswith(".pdf"):
                try:
                    section_map = parse_coi_expirations(abs_coi)  # {'A': {...}, ...}
                    # grava dicionário simples { 'A': 'YYYY-MM-DD', ... }
                    simple_sections = {}
                    for letter, info in section_map.items():
                        dt = info.get("expires_at")
                        if dt:
                            simple_sections[letter] = dt.strftime("%Y-%m-%d")
                    if simple_sections:
                        docs["coi_sections"] = simple_sections

                    analysis = analyze_coi_expirations(section_map)
                    if analysis.get("nearest"):
                        letter, dt, days_left, label = analysis["nearest"]
                        cat, lvl = coi_alert_level(days_left)
                        flash(f"COI: vence primeiro {letter} - {label} em {dt.strftime('%m/%d/%Y')} (faltam {days_left} dias) • {lvl}", cat)

                    # dispara um alerta por seção, com cor por faixa (60,45,30,15,5,0)
                    for letter, dt, days_left, label in analysis.get("ordered", []):
                        cat, lvl = coi_alert_level(days_left)
                        flash(f"COI • Seção {letter} - {label}: expira em {dt.strftime('%m/%d/%Y')} (faltam {days_left} dias) • {lvl}", cat)

                except Exception as e:
                    flash(f"Não consegui ler seções A..E do COI: {e}", "warning")

            # 2) Fallback/compatível: detecta validade geral (lógica genérica)
            if coi_path.lower().endswith(".pdf"):
                expiry = detect_expiry_from_pdf(abs_coi)
                if expiry:
                    docs["coi_expiry"] = expiry
                    try:
                        d = datetime.strptime(expiry, "%Y-%m-%d").date()
                        if d < date.today():
                            flash(f"COI (validade geral) está VENCIDO: {expiry}.", "danger")
                        else:
                            days_left = (d - date.today()).days
                            cat, lvl = coi_alert_level(days_left)
                            flash(f"COI (validade geral): {expiry} • {lvl}", cat)
                    except Exception:
                        pass

        # Campo manual de validade do COI (opcional)
        coi_expiry_manual = request.form.get("coi_expiry", "").strip()
        if coi_expiry_manual and not docs.get("coi_expiry"):
            d = parse_date_yyyy_mm_dd(coi_expiry_manual)
            if d:
                docs["coi_expiry"] = d.strftime("%Y-%m-%d")
            else:
                flash("Data de validade do COI inválida (use AAAA-MM-DD).", "warning")

        u["profile"]["onboarding"]["step2"] = all([
            docs.get("ein_path"),
            docs.get("w9_path"),
            docs.get("coi_path"),
        ])

        save_data(data)
        flash("Etapa 2 salva.", "success")
        return redirect(url_for("contractor"))

    # Passa também as seções (se quiser exibir no template)
    coi_sections = docs.get("coi_sections", {})
    return render_template("contractor_step2.html", docs=docs, user=u, coi_sections=coi_sections)


# --------- Contractor: Etapa 3 (termo de conduta) — CORRIGIDO ---------
@app.route("/contractor/step3", methods=["GET", "POST"])
@login_required
@role_required("contractor", "admin")
def contractor_step3():
    data = load_data()
    u = get_user_dict(data, current_user.id)
    terms = u["profile"]["terms"]

    if request.method == "POST":
        tech = request.form.get("tech") == "on"
        mgmt = request.form.get("mgmt") == "on"
        behavior = request.form.get("behavior") == "on"

        terms["tech"] = tech
        terms["mgmt"] = mgmt
        terms["behavior"] = behavior

        # Correção: condição válida em Python
        if tech and mgmt and behavior:
            terms["signed_at"] = datetime.utcnow().isoformat()
            u["profile"]["onboarding"]["step3"] = True
            flash("Termo assinado com sucesso.", "success")
        else:
            u["profile"]["onboarding"]["step3"] = False
            flash("Para concluir a etapa, marque as três opções.", "warning")

        save_data(data)
        return redirect(url_for("contractor"))

    return render_template("contractor_step3.html", terms=terms, user=u)


# ---------------------- SERVE UPLOADS ----------------------
@app.route("/uploads/<path:filename>")
@login_required
def serve_uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


# ---------------------- SUBCONTRACTOR ----------------------
@app.route("/subcontractor", methods=["GET", "POST"])
@login_required
@role_required("subcontractor", "admin")
def subcontractor():
    data = load_data()
    if request.method == "POST":
        service_id = request.form["service_id"]
        bid = float(request.form["bid"])
        for service in data["services"]:
            if service["id"] == service_id:
                service["bids"].append({"value": bid, "user_id": current_user.id})
                best = min(service["bids"], key=lambda x: x["value"])
                service["winner"] = best["value"]
                service["winner_user_id"] = best.get("user_id")
                break
        save_data(data)
        flash("Lance enviado!", "success")
        return redirect(url_for("subcontractor"))

    users_index = {u["id"]: u for u in data["users"]}
    return render_template("subcontractor.html", services=data["services"], users_index=users_index)


# ---------------------- ADMIN (Dashboard) ----------------------
@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    data = load_data()
    total_services = len(data["services"])
    total_bids = sum(len(s.get("bids", [])) for s in data["services"])
    winners = [s for s in data["services"] if s.get("winner") is not None]
    pending_users = [u for u in data["users"]
                     if u["role"] in ("contractor", "subcontractor") and u["status"] == "pending"]

    def build_rows(role_name: str):
        rows = []
        for u in data["users"]:
            if u.get("role") != role_name:
                continue
            prof = u.get("profile", {})
            docs = prof.get("docs", {})
            terms = prof.get("terms", {})
            ob = compute_onboarding_info(u)
            ein_url = url_for("serve_uploads", filename=docs["ein_path"]) if docs.get("ein_path") else None
            w9_url  = url_for("serve_uploads", filename=docs["w9_path"]) if docs.get("w9_path") else None
            coi_url = url_for("serve_uploads", filename=docs["coi_path"]) if docs.get("coi_path") else None

            ein_exp = docs.get("ein_expiry")
            w9_exp  = docs.get("w9_expiry")
            coi_exp = docs.get("coi_expiry")

            rows.append({
                "id": u["id"],
                "name": u.get("name"),
                "email": u.get("email"),
                "status": u.get("status"),
                "percent": ob["percent"],
                "s1": ob["step1"], "s2": ob["step2"], "s3": ob["step3"],
                "ein_url": ein_url, "w9_url": w9_url, "coi_url": coi_url,
                "ein_expiry": ein_exp, "w9_expiry": w9_exp, "coi_expiry": coi_exp,
                "ein_state": expiry_state(ein_exp), "w9_state": expiry_state(w9_exp), "coi_state": expiry_state(coi_exp),
                "terms": {
                    "tech": terms.get("tech"),
                    "mgmt": terms.get("mgmt"),
                    "behavior": terms.get("behavior"),
                    "signed_at": terms.get("signed_at")
                }
            })
        return rows

    contractor_users = build_rows("contractor")
    subcontractor_users = build_rows("subcontractor")

    # Resumo de expirações (vencendo em 30 dias ou vencidos) — visão geral
    alerts = []
    for role, rows in (("contractor", contractor_users), ("subcontractor", subcontractor_users)):
        for r in rows:
            for doc_key, state in (("EIN", r["ein_state"]), ("W-9", r["w9_state"]), ("COI", r["coi_state"])):
                if state["state"] in ("warn", "expired"):
                    alerts.append({
                        "role": role, "name": r["name"], "email": r["email"],
                        "doc": doc_key, "status": state["state"], "label": state["label"],
                        "date": r[f"{doc_key.lower().replace('-', '')}_expiry"]
                    })

    expiring_count = sum(1 for a in alerts if a["status"] == "warn")
    expired_count  = sum(1 for a in alerts if a["status"] == "expired")

    users_index = {u["id"]: u for u in data["users"]}

    return render_template(
        "admin.html",
        services=data["services"],
        total_services=total_services,
        total_bids=total_bids,
        winners=len(winners),
        pending_users=pending_users,
        contractor_users=contractor_users,
        subcontractor_users=subcontractor_users,
        expiring_alerts=alerts,
        expiring_count=expiring_count,
        expired_count=expired_count,
        users_index=users_index
    )


# --------- Admin: Aprovar / Rejeitar ---------
@app.route("/admin/users/approve/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def approve_user(user_id):
    data = load_data()
    for u in data["users"]:
        if u["id"] == user_id:
            u["status"] = "approved"
            save_data(data)
            flash("Usuário aprovado.", "success")
            break
    return redirect(url_for("admin"))


@app.route("/admin/users/reject/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def reject_user(user_id):
    data = load_data()
    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u["id"] != user_id]
    save_data(data)
    flash("Usuário rejeitado e removido." if len(data["users"]) < before else "Usuário não encontrado.", "info")
    return redirect(url_for("admin"))


# --------- Admin: Criar usuário (entra aprovado) ---------
@app.route("/admin/users/create", methods=["POST"])
@login_required
@role_required("admin")
def admin_create_user():
    role = request.form.get("role")
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    if role not in ("contractor", "subcontractor", "admin"):
        flash("Papel inválido.", "danger"); return redirect(url_for("admin"))
    if not name or not email or not password:
        flash("Preencha nome, e-mail e senha.", "warning"); return redirect(url_for("admin"))
    data = load_data()
    if any(u["email"].lower() == email.lower() for u in data["users"]):
        flash("E-mail já existente.", "warning"); return redirect(url_for("admin"))

    data["users"].append({
        "id": str(uuid.uuid4()),
        "email": email,
        "name": name,
        "role": role,
        "status": "approved",
        "password_hash": generate_password_hash(password),
        "profile": {
            "basic": {}, "docs": {}, "terms": {},
            "onboarding": {"step1": False, "step2": False, "step3": False}
        }
    })
    save_data(data)
    flash(f"Usuário {name} criado como {role} (aprovado).", "success")
    return redirect(url_for("admin"))


# ---------------------- API de Notificações (badge do sino) ----------------------
@app.route("/api/pending_count")
@login_required
@role_required("admin")
def api_pending_count():
    data = load_data()
    pending = [u for u in data["users"]
               if u["role"] in ("contractor", "subcontractor") and u["status"] == "pending"]
    return jsonify({"count": len(pending)})


# ---------------------- Boot ----------------------
if __name__ == "__main__":
    create_default_admin_if_missing()
    app.run(debug=True)
