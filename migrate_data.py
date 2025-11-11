import json, uuid, re, shutil, os

DATA_FILE = "data.json"
BACKUP_FILE = "data.backup.json"

def to_float_br(s):
    s = s.strip()
    s = re.sub(r"[^\d,.\-]", "", s)  # remove $, espaços etc.
    s = s.replace(".", "").replace(",", ".")  # 3.000,00 -> 3000.00
    try:
        return float(s)
    except:
        return None

with open(DATA_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# Backup
shutil.copyfile(DATA_FILE, BACKUP_FILE)

# Garante users
if "users" not in data:
    data["users"] = []

# Normaliza serviços
services = data.get("services", [])
for s in services:
    # id
    if "id" not in s or not s["id"]:
        s["id"] = str(uuid.uuid4())

    # owner_id (opcional)
    s.setdefault("owner_id", None)

    # price_range -> "min-max"
    pr = s.get("price_range")
    if pr:
        # Se já estiver no formato "x-y", mantem (corrige invertido se preciso)
        if isinstance(pr, str) and "-" in pr:
            try:
                a, b = pr.split("-", 1)
                a = to_float_br(a)
                b = to_float_br(b)
                if a is not None and b is not None:
                    lo, hi = (a, b) if a <= b else (b, a)
                    s["price_range"] = f"{int(lo) if lo.is_integer() else lo}-{int(hi) if hi.is_integer() else hi}"
                else:
                    s["price_range"] = "0-999999"
            except:
                s["price_range"] = "0-999999"
        else:
            # Valor único -> vira faixa 0-valor
            v = to_float_br(str(pr))
            s["price_range"] = f"0-{int(v) if v and float(v).is_integer() else (v if v else 999999)}"
    else:
        s["price_range"] = "0-999999"

    # bids: lista de números -> lista de objetos
    bids = s.get("bids", [])
    new_bids = []
    for b in bids:
        if isinstance(b, dict) and "value" in b:
            new_bids.append(b)
        else:
            try:
                new_bids.append({"value": float(b), "user_id": None})
            except:
                pass
    s["bids"] = new_bids

    # winner: mantém número; se quiser recalcular:
    if s["bids"]:
        winner_val = min(s["bids"], key=lambda x: x["value"])["value"]
        s["winner"] = winner_val
    else:
        s["winner"] = None

# Salva
with open(DATA_FILE, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print("Migração concluída. Backup em", BACKUP_FILE)
