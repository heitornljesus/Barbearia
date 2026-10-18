from __future__ import annotations

import os
import secrets
import sqlite3
import uuid
from datetime import date, datetime, time, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("BARBEARIA_DATA_DIR", ROOT / "data"))
PHOTOS = DATA / "produtos"
DB = DATA / "barbearia.sqlite3"
app = Flask(__name__)
app.secret_key = os.environ.get("BARBEARIA_SECRET_KEY", "") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("BARBEARIA_HTTPS") == "1"
FORMATS = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}
SERVICE_CARDS = [
    {"name": "Corte", "icon": "✂", "description": "Clássico, degradê ou do seu jeito."},
    {"name": "Sobrancelha", "icon": "⌁", "description": "Design e acabamento da sobrancelha."},
    {"name": "Corte+sobrancelha", "icon": "✦", "description": "Corte alinhado com sobrancelha feita."},
    {"name": "Barba", "icon": "◒", "description": "Acabamento alinhado e cuidado completo."},
    {"name": "Corte+Barba", "icon": "✧", "description": "Corte e barba no mesmo atendimento."},
    {"name": "Corte+sobrancelha+barba", "icon": "✦", "description": "O trato completo, do cabelo à barba."},
    {"name": "Limpeza de pele", "icon": "◉", "description": "Cuidado facial para renovar a pele."},
]
SERVICES = tuple(service["name"] for service in SERVICE_CARDS)


def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    DATA.mkdir(parents=True, exist_ok=True)
    PHOTOS.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('supervisor','barber','customer')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS appointments (
          id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES users(id),
          barber_id INTEGER REFERENCES users(id),
          service TEXT NOT NULL, starts_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pendente'
            CHECK(status IN ('Pendente','Confirmado','Cancelado')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS products (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          price_cents INTEGER NOT NULL CHECK(price_cents >= 0), photo TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        appointment_columns = {row["name"] for row in db.execute("PRAGMA table_info(appointments)")}
        if "barber_id" not in appointment_columns:
            db.execute("ALTER TABLE appointments ADD COLUMN barber_id INTEGER REFERENCES users(id)")
        db.execute("DROP INDEX IF EXISTS one_active_booking_per_slot")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_active_booking_per_barber_slot
                     ON appointments(barber_id, starts_at) WHERE status != 'Cancelado'""")
        first_barber = db.execute("SELECT id FROM users WHERE role='barber' ORDER BY id LIMIT 1").fetchone()
        if first_barber:
            db.execute("UPDATE appointments SET barber_id=? WHERE barber_id IS NULL", (first_barber["id"],))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def protect_forms():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        saved = session.get("csrf", "")
        if not saved or not secrets.compare_digest(sent, saved):
            abort(400, "Formulário expirado. Atualize a página e tente novamente.")


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "current_user": g.get("user")}


@app.before_request
def load_user():
    user_id = session.get("user_id")
    if user_id:
        with connect() as db:
            g.user = db.execute("SELECT id,name,email,role FROM users WHERE id=?", (user_id,)).fetchone()
    else:
        g.user = None


def login_required(*roles):
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login", next=request.path))
            if roles and g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorate


def money(cents):
    return f"R$ {cents / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


app.add_template_filter(money, "brl")


@app.get("/")
def home():
    with connect() as db:
        products = db.execute("SELECT * FROM products WHERE active=1 ORDER BY created_at DESC LIMIT 12").fetchall()
    return render_template("home.html", products=products, service_cards=SERVICE_CARDS)


@app.route("/cadastro", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, password = (request.form.get(k, "").strip() for k in ("name", "email", "password"))
        if not name or "@" not in email or len(password) < 8:
            flash("Informe nome, e-mail válido e senha com pelo menos 8 caracteres.", "error")
        else:
            try:
                with connect() as db:
                    db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')",
                               (name, email.lower(), generate_password_hash(password)))
                flash("Conta criada. Você já pode entrar e agendar.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.", "error")
    return render_template("auth.html", mode="register")


@app.route("/entrar", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        with connect() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()
            destination = request.args.get("next", "")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("home")
            return redirect(destination)
        flash("E-mail ou senha incorretos.", "error")
    return render_template("auth.html", mode="login")


@app.get("/sair")
def logout():
    session.clear()
    return redirect(url_for("home"))


def available_slots(day: date, barber_id: int):
    now = datetime.now()
    slots = []
    for hour in range(9, 19):
        for minute in (0, 30):
            start = datetime.combine(day, time(hour, minute))
            if start.time() >= time(19, 0):
                continue
            if start > now + timedelta(minutes=15):
                slots.append(start)
    with connect() as db:
        taken = {r[0] for r in db.execute(
            "SELECT starts_at FROM appointments WHERE barber_id=? AND date(starts_at)=? AND status!='Cancelado'",
            (barber_id, day.isoformat())
        ).fetchall()}
    return [s for s in slots if s.strftime("%Y-%m-%d %H:%M") not in taken]


@app.route("/agendar", methods=["GET", "POST"])
@login_required("customer")
def book():
    day_text = request.values.get("day", date.today().isoformat())
    try:
        selected_day = date.fromisoformat(day_text)
    except ValueError:
        selected_day = date.today()
    barber_text = request.values.get("barber_id", "").strip()
    try:
        selected_barber_id = int(barber_text)
    except ValueError:
        selected_barber_id = None
    with connect() as db:
        barbers = db.execute("SELECT id,name FROM users WHERE role='barber' ORDER BY name COLLATE NOCASE").fetchall()
    selected_barber = next((barber for barber in barbers if barber["id"] == selected_barber_id), None)
    if request.method == "POST":
        chosen = request.form.get("slot", "")
        service = request.form.get("service", "")
        if not selected_barber:
            flash("Escolha um barbeiro cadastrado.", "error")
        elif service not in SERVICES:
            flash("Escolha um serviço válido.", "error")
        else:
            slots = available_slots(selected_day, selected_barber_id)
            if not any(s.strftime("%Y-%m-%d %H:%M") == chosen for s in slots):
                flash("Esse horário não está mais disponível. Escolha outro.", "error")
            else:
                try:
                    with connect() as db:
                        db.execute("INSERT INTO appointments(customer_id,barber_id,service,starts_at) VALUES(?,?,?,?)",
                                   (g.user["id"], selected_barber_id, service, chosen))
                    flash("Pedido de agendamento enviado para confirmação.", "success")
                    return redirect(url_for("my_appointments"))
                except sqlite3.IntegrityError:
                    flash("Esse horário acabou de ser reservado. Escolha outro.", "error")
    slots = available_slots(selected_day, selected_barber_id) if selected_barber and selected_day >= date.today() else []
    return render_template("booking.html", day=selected_day.isoformat(), min_day=date.today().isoformat(),
                           slots=slots, barbers=barbers, selected_barber_id=selected_barber_id,
                           services=SERVICES)


@app.get("/meus-agendamentos")
@login_required("customer")
def my_appointments():
    with connect() as db:
        appointments = db.execute("""SELECT a.*, b.name AS barber_name FROM appointments a
                                  LEFT JOIN users b ON b.id=a.barber_id
                                  WHERE a.customer_id=? ORDER BY a.starts_at DESC""",
                                  (g.user["id"],)).fetchall()
    return render_template("appointments.html", appointments=appointments, supervisor=False)


@app.get("/supervisor/agendamentos")
@login_required("barber")
def manage_appointments():
    with connect() as db:
        appointments = db.execute("""SELECT a.*, u.name AS customer_name, u.email AS customer_email,
          b.name AS barber_name FROM appointments a JOIN users u ON u.id=a.customer_id
          JOIN users b ON b.id=a.barber_id WHERE a.barber_id=? ORDER BY a.starts_at DESC""",
                                  (g.user["id"],)).fetchall()
    return render_template("appointments.html", appointments=appointments, supervisor=True)


@app.post("/supervisor/agendamento/<int:appointment_id>")
@login_required("barber")
def update_appointment(appointment_id):
    status = request.form.get("status")
    if status not in ("Confirmado", "Cancelado"):
        abort(400)
    with connect() as db:
        updated = db.execute("UPDATE appointments SET status=? WHERE id=? AND barber_id=?",
                             (status, appointment_id, g.user["id"]))
        if updated.rowcount == 0:
            abort(404)
    flash("Agendamento atualizado.", "success")
    return redirect(url_for("manage_appointments"))


@app.route("/supervisor/barbeiros", methods=["GET", "POST"])
@login_required("supervisor")
def manage_barbers():
    if request.method == "POST":
        name, email, password = (request.form.get(k, "").strip() for k in ("name", "email", "password"))
        if not name or "@" not in email or len(password) < 8:
            flash("Informe nome, e-mail válido e senha com pelo menos 8 caracteres.", "error")
        else:
            try:
                with connect() as db:
                    created = db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'barber')",
                                         (name, email.lower(), generate_password_hash(password)))
                    first_barber = db.execute("SELECT id FROM users WHERE role='barber' ORDER BY id LIMIT 1").fetchone()
                    if first_barber and first_barber["id"] == created.lastrowid:
                        db.execute("UPDATE appointments SET barber_id=? WHERE barber_id IS NULL", (created.lastrowid,))
                flash("Acesso do barbeiro criado.", "success")
                return redirect(url_for("manage_barbers"))
            except sqlite3.IntegrityError:
                flash("Este e-mail já está cadastrado.", "error")
    with connect() as db:
        barbers = db.execute("SELECT id,name,email FROM users WHERE role='barber' ORDER BY name").fetchall()
    return render_template("barbers.html", barbers=barbers)


def store_photo(upload):
    if not upload or not upload.filename:
        return ""
    upload.stream.seek(0, 2)
    if upload.stream.tell() > 8 * 1024 * 1024:
        raise ValueError("A imagem deve ter no máximo 8 MB.")
    upload.stream.seek(0)
    try:
        with Image.open(upload.stream) as image:
            fmt = image.format
            image.verify()
    except (UnidentifiedImageError, OSError):
        raise ValueError("O arquivo não é uma imagem válida.") from None
    if fmt not in FORMATS:
        raise ValueError("Use imagem JPG, PNG ou WebP.")
    name = uuid.uuid4().hex + FORMATS[fmt]
    upload.stream.seek(0)
    with Image.open(upload.stream) as image:
        image.thumbnail((1600, 1600))
        image.save(PHOTOS / name, format=fmt, optimize=True)
    return name


@app.route("/produtos/novo", methods=["GET", "POST"])
@login_required("barber")
def new_product():
    if request.method == "POST":
        filename = ""
        try:
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            price = round(float(request.form.get("price", "0").replace(",", ".")) * 100)
            if not name or price < 0:
                raise ValueError("Informe nome e preço válido.")
            filename = store_photo(request.files.get("photo"))
            with connect() as db:
                db.execute("INSERT INTO products(name,description,price_cents,photo) VALUES(?,?,?,?)",
                           (name, description, price, filename))
            flash("Produto publicado na vitrine.", "success")
            return redirect(url_for("home"))
        except ValueError as e:
            if filename:
                (PHOTOS / filename).unlink(missing_ok=True)
            flash(str(e), "error")
    return render_template("product_form.html")


@app.post("/produtos/<int:product_id>/excluir")
@login_required("barber")
def remove_product(product_id):
    with connect() as db:
        product = db.execute("SELECT photo FROM products WHERE id=?", (product_id,)).fetchone()
        if product:
            db.execute("UPDATE products SET active=0 WHERE id=?", (product_id,))
    if product and product["photo"]:
        (PHOTOS / product["photo"]).unlink(missing_ok=True)
    flash("Produto removido da vitrine.", "success")
    return redirect(url_for("home"))


@app.get("/fotos/<path:filename>")
def product_photo(filename):
    from flask import send_from_directory
    return send_from_directory(PHOTOS, filename)


@app.errorhandler(413)
def too_big(_error):
    flash("A imagem deve ter no máximo 8 MB.", "error")
    return redirect(request.referrer or url_for("home"))


@app.cli.command("create-supervisor")
def create_supervisor():
    """Create first supervisor account from the command line."""
    import getpass
    name = input("Nome do supervisor: ").strip()
    email = input("E-mail: ").strip().lower()
    password = getpass.getpass("Senha (mínimo 8 caracteres): ")
    if not name or "@" not in email or len(password) < 8:
        raise SystemExit("Nome, e-mail válido e senha de pelo menos 8 caracteres são obrigatórios.")
    try:
        with connect() as db:
            db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'supervisor')",
                       (name, email, generate_password_hash(password)))
        print("Supervisor criado. Entre no site para cadastrar barbeiros.")
    except sqlite3.IntegrityError:
        raise SystemExit("Este e-mail já está cadastrado.")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
