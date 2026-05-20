import os
import sqlite3
import uuid
from datetime import date, datetime
from math import ceil

from flask import Flask, abort, redirect, render_template, request, session, url_for, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import logging
import traceback

app = Flask(__name__)

# Production-ready configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
)

UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('spotly.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Rate limiting storage (simple in-memory for demo)
rate_limit_storage = {}


@app.before_request
def before_request():
    """Security headers and rate limiting."""
    # Security headers
    if request.endpoint and request.endpoint.startswith('static'):
        return  # Skip static files
    
    # Add security headers
    response = None
    
    # Rate limiting for sensitive endpoints
    if request.endpoint in ['signup', 'login']:
        client_ip = request.remote_addr
        key = f"{client_ip}:{request.endpoint}"
        now = datetime.now().timestamp()
        
        if key not in rate_limit_storage:
            rate_limit_storage[key] = []
        
        # Clean old requests (older than 1 minute)
        rate_limit_storage[key] = [t for t in rate_limit_storage[key] if now - t < 60]
        
        # Check rate limit (max 5 requests per minute)
        if len(rate_limit_storage[key]) >= 5:
            return "Rate limit exceeded", 429
        
        rate_limit_storage[key].append(now)
    
    return response


@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    if request.endpoint and request.endpoint.startswith('static'):
        return response  # Skip static files
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    
    return response


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logger.warning(f"404 error: {request.url}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"500 error: {request.url} - {str(error)}")
    logger.error(traceback.format_exc())
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500


@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limiting errors."""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({'error': 'Rate limit exceeded'}), 429


def _db():
    conn = sqlite3.connect("spotly.db")
    conn.row_factory = sqlite3.Row
    return conn


def _validate_email(email: str) -> bool:
    """Validate email format."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def _validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"


def _sanitize_string(text: str, max_length: int = 255) -> str:
    """Sanitize and truncate string input."""
    if not text:
        return ""
    # Remove potential HTML tags and limit length
    import re
    text = re.sub(r'<[^>]+>', '', text)
    text = text.strip()[:max_length]
    return text


def _validate_date(date_str: str) -> bool:
    """Validate date format and ensure it's not in the past."""
    try:
        parsed_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        return parsed_date >= date.today()
    except ValueError:
        return False


def _init_db():
    with _db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              creator_email TEXT NOT NULL,
              title TEXT NOT NULL,
              event_date TEXT NOT NULL,
              venue TEXT NOT NULL,
              description TEXT NOT NULL,
              thumbnail_path TEXT,
              views INTEGER NOT NULL DEFAULT 0,
              is_archived INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        try:
            conn.execute("ALTER TABLE events ADD COLUMN views INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute(
                "ALTER TABLE events ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              customer_email TEXT NOT NULL,
              event_id INTEGER NOT NULL,
              amount INTEGER NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              booking_date TEXT NOT NULL DEFAULT (datetime('now')),
              customer_id INTEGER,
              paid_at TEXT,
              canceled_at TEXT,
              refund_amount INTEGER,
              refund_fee_percent INTEGER,
              FOREIGN KEY(event_id) REFERENCES events(id)
            )
            """
        )

        try:
            conn.execute(
                "ALTER TABLE bookings ADD COLUMN booking_date TEXT NOT NULL DEFAULT (datetime('now'))"
            )
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE bookings ADD COLUMN customer_id INTEGER")
        except sqlite3.OperationalError:
            pass

        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_bookings_unique_active
            ON bookings(customer_email, event_id)
            WHERE status != 'canceled'
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS venues (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              manager_email TEXT NOT NULL,
              name TEXT NOT NULL,
              city TEXT NOT NULL,
              address TEXT NOT NULL,
              capacity INTEGER NOT NULL,
              price_per_day INTEGER NOT NULL,
              price_per_hour INTEGER NOT NULL,
              amenities TEXT NOT NULL,
              description TEXT NOT NULL,
              images TEXT,
              is_active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS venue_bookings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              venue_id INTEGER NOT NULL,
              event_title TEXT NOT NULL,
              creator_email TEXT NOT NULL,
              requested_date TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY(venue_id) REFERENCES venues(id)
            )
            """
        )


_init_db()

@app.get("/")
def index():
    return render_template("index.html", user=_current_user())


def _current_user():
    email = session.get("user_email")
    role = session.get("user_role")
    if not email or role not in ("audience", "creator", "venue_manager"):
        return None
    return {"email": email, "role": role}


@app.context_processor
def _inject_user():
    return {"user": _current_user()}


def _require_login():
    user = _current_user()
    if not user:
        return redirect(url_for("login_page"))
    return user


def _require_role(expected_role: str):
    user = _require_login()
    if not isinstance(user, dict):
        return user
    if user["role"] != expected_role:
        abort(403)
    return user


def _get_page_args(default_per_page: int = 6) -> tuple[int, int]:
    raw_page = request.args.get("page")
    raw_per_page = request.args.get("per_page")

    try:
        page = int(raw_page) if raw_page is not None else 1
    except ValueError:
        page = 1

    try:
        per_page = int(raw_per_page) if raw_per_page is not None else default_per_page
    except ValueError:
        per_page = default_per_page

    if page < 1:
        page = 1
    if per_page < 1:
        per_page = default_per_page
    if per_page > 24:
        per_page = 24

    return page, per_page


def _pagination_model(page: int, per_page: int, total: int) -> dict:
    pages = max(1, int(ceil(total / per_page)))
    if page > pages:
        page = pages

    window = 2
    start = max(1, page - window)
    end = min(pages, page + window)
    page_numbers = list(range(start, end + 1))

    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": page - 1,
        "next_page": page + 1,
        "page_numbers": page_numbers,
        "offset": (page - 1) * per_page,
    }


SIGNUP_REGISTER = {
    "audience": {
        "icon": "🎫",
        "badge": "Audience",
        "title": "Join as an attendee",
        "subtitle": "Discover shows and book tickets in one place.",
        "name_label": "Full name",
        "name_placeholder": "Your full name",
        "email_placeholder": "you@email.com",
        "submit": "Create account",
    },
    "creator": {
        "icon": "🎤",
        "badge": "Creator",
        "title": "Join as a creator",
        "subtitle": "Publish events and grow your audience.",
        "name_label": "Creator name",
        "name_placeholder": "Stage name or brand",
        "email_placeholder": "creator@yourbrand.com",
        "submit": "Create creator account",
    },
    "venue_manager": {
        "icon": "🏛️",
        "badge": "Venue",
        "title": "Join as a venue",
        "subtitle": "List your space and manage bookings.",
        "name_label": "Venue name",
        "name_placeholder": "Venue or company name",
        "email_placeholder": "venue@yourcompany.com",
        "submit": "Create venue account",
    },
}


def _signup_register_page(role: str):
    meta = SIGNUP_REGISTER.get(role)
    if not meta:
        return redirect(url_for("signup_page"))
    return render_template(
        "signup_register.html",
        role=role,
        error=request.args.get("error"),
        **meta,
    )


@app.get("/signup-role")
def signup_role_selection_page():
    return redirect(url_for("signup_page"))


@app.get("/signup-audience")
def signup_audience_page():
    return _signup_register_page("audience")


@app.get("/signup-creator")
def signup_creator_page():
    return _signup_register_page("creator")


@app.get("/signup-venue")
@app.get("/signup-venue_manager")
def signup_venue_page():
    return _signup_register_page("venue_manager")


@app.get("/signup")
def signup_page():
    return render_template("signup.html")


@app.get("/login")
def login_page():
    role = (request.args.get("role") or "audience").strip().lower()
    if role == "venue":
        role = "venue_manager"
    if role not in ("audience", "creator", "venue_manager"):
        role = "audience"
    error = request.args.get("error")
    return render_template("login.html", role=role, error=error)


@app.get("/featured-shows")
def featured_shows_page():
    return render_template("featured_shows.html", user=_current_user())


@app.get("/live-shows")
def live_shows_page():
    return render_template("live_shows.html", user=_current_user())


@app.get("/testimonials")
def testimonials_page():
    return render_template("testimonials.html", user=_current_user())


@app.get("/creator")
def creator_dashboard():
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user

    today = date.today()
    page, per_page = _get_page_args(default_per_page=6)
    with _db() as conn:
        total = (
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE creator_email = ?",
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        p = _pagination_model(page, per_page, total)

        stats_total_events = (
            conn.execute(
                "SELECT COUNT(*) FROM events WHERE creator_email = ?",
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        stats_page_views = (
            conn.execute(
                "SELECT COALESCE(SUM(views),0) FROM events WHERE creator_email = ?",
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        stats_total_bookings = (
            conn.execute(
                """
                SELECT COUNT(*)
                FROM bookings b
                JOIN events e ON e.id = b.event_id
                WHERE e.creator_email = ? AND b.status != 'canceled'
                """,
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        stats_total_revenue = (
            conn.execute(
                """
                SELECT COALESCE(SUM(b.amount),0)
                FROM bookings b
                JOIN events e ON e.id = b.event_id
                WHERE e.creator_email = ? AND b.status != 'canceled'
                """,
                (user["email"],),
            ).fetchone()[0]
            or 0
        )

        events = conn.execute(
            """
            SELECT
              e.*,
              COALESCE(SUM(CASE WHEN b.status != 'canceled' THEN 1 ELSE 0 END),0) AS booking_count,
              COALESCE(SUM(CASE WHEN b.status != 'canceled' THEN b.amount ELSE 0 END),0) AS revenue
            FROM events e
            LEFT JOIN bookings b ON b.event_id = e.id
            WHERE e.creator_email = ?
            GROUP BY e.id
            ORDER BY e.event_date ASC
            LIMIT ? OFFSET ?
            """,
            (user["email"], p["per_page"], p["offset"]),
        ).fetchall()

        recent_bookings = conn.execute(
            """
            SELECT
              b.created_at as ts,
              e.title as title,
              COUNT(*) as cnt
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE e.creator_email = ? AND b.status != 'canceled'
            GROUP BY date(b.created_at), e.id
            ORDER BY b.created_at DESC
            LIMIT 6
            """,
            (user["email"],),
        ).fetchall()
        recent_events = conn.execute(
            """
            SELECT created_at as ts, title as title
            FROM events
            WHERE creator_email = ?
            ORDER BY created_at DESC
            LIMIT 6
            """,
            (user["email"],),
        ).fetchall()

        activity = []
        for r in recent_bookings:
            activity.append(
                {
                    "icon": "🎟️",
                    "text": f"{r['cnt']} ticket(s) booked for {r['title']}",
                    "ts": r["ts"],
                }
            )
        for r in recent_events:
            activity.append(
                {"icon": "✨", "text": f"Event published: {r['title']}", "ts": r["ts"]}
            )
        activity = sorted(activity, key=lambda x: x["ts"], reverse=True)[:8]

        upcoming = conn.execute(
            """
            SELECT id, title, event_date, venue
            FROM events
            WHERE creator_email = ? AND is_archived = 0
            ORDER BY event_date ASC
            LIMIT 6
            """,
            (user["email"],),
        ).fetchall()

        upcoming_today = []
        upcoming_week = []
        upcoming_month = []
        for r in upcoming:
            try:
                d = datetime.strptime(r["event_date"], "%Y-%m-%d").date()
            except ValueError:
                continue
            delta = (d - today).days
            if delta < 0:
                continue
            if delta == 0:
                upcoming_today.append(r)
            elif delta <= 7:
                upcoming_week.append(r)
            elif d.year == today.year and d.month == today.month:
                upcoming_month.append(r)
    return render_template(
        "creator.html",
        user_email=user["email"],
        events=events,
        pagination=p,
        stats={
            "total_events": int(stats_total_events),
            "total_bookings": int(stats_total_bookings),
            "total_revenue": int(stats_total_revenue),
            "page_views": int(stats_page_views),
            "trend": {"total_events": 0, "total_bookings": 0, "total_revenue": 0, "page_views": 0},
        },
        activity=activity,
        upcoming={"today": upcoming_today, "week": upcoming_week, "month": upcoming_month},
        today=today,
        public_booking_url=request.url_root.rstrip("/") + "/customer",
    )


@app.get("/creator/events/<int:event_id>/edit")
def creator_edit_event_page(event_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        event = conn.execute(
            "SELECT * FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        ).fetchone()
    if not event:
        abort(404)
    return render_template("creator_event_edit.html", user_email=user["email"], event=event)


@app.post("/creator/events/<int:event_id>/edit")
def creator_edit_event_submit(event_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user

    title = (request.form.get("title") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()
    venue = (request.form.get("venue") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not title or not event_date or not venue or not description:
        return redirect(url_for("creator_edit_event_page", event_id=event_id) + "?error=missing")

    thumb = request.files.get("thumbnail")
    thumb_path = None
    if thumb and (thumb.filename or "").strip():
        raw = secure_filename(thumb.filename)
        ext = os.path.splitext(raw)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".webp"):
            return redirect(url_for("creator_edit_event_page", event_id=event_id) + "?error=thumb")
        fname = f"{uuid.uuid4().hex}{ext}"
        abs_path = os.path.join(UPLOAD_DIR, fname)
        try:
            thumb.save(abs_path)
            thumb_path = f"uploads/{fname}"
        except Exception as e:
            # Log the error and continue without thumbnail
            print(f"Error saving thumbnail: {e}")
            thumb_path = None

    with _db() as conn:
        existing = conn.execute(
            "SELECT * FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        ).fetchone()
        if not existing:
            abort(404)
        if thumb_path:
            conn.execute(
                """
                UPDATE events
                SET title = ?, event_date = ?, venue = ?, description = ?, thumbnail_path = ?
                WHERE id = ? AND creator_email = ?
                """,
                (title, event_date, venue, description, thumb_path, event_id, user["email"]),
            )
        else:
            conn.execute(
                """
                UPDATE events
                SET title = ?, event_date = ?, venue = ?, description = ?
                WHERE id = ? AND creator_email = ?
                """,
                (title, event_date, venue, description, event_id, user["email"]),
            )
    return redirect(url_for("creator_dashboard"))


@app.post("/creator/events/<int:event_id>/archive")
def creator_archive_event(event_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        row = conn.execute(
            "SELECT is_archived FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        ).fetchone()
        if not row:
            abort(404)
        next_val = 0 if int(row["is_archived"] or 0) == 1 else 1
        conn.execute(
            "UPDATE events SET is_archived = ? WHERE id = ? AND creator_email = ?",
            (next_val, event_id, user["email"]),
        )
    return redirect(url_for("creator_dashboard"))


@app.post("/creator/events/<int:event_id>/delete")
def creator_delete_event(event_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        ok = conn.execute(
            "SELECT 1 FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        ).fetchone()
        if not ok:
            abort(404)
        conn.execute("DELETE FROM bookings WHERE event_id = ?", (event_id,))
        conn.execute(
            "DELETE FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        )
    return redirect(url_for("creator_dashboard"))


@app.get("/creator/venues")
def creator_venues_page():
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user

    page, per_page = _get_page_args(default_per_page=9)
    try:
        with _db() as conn:
            total = (
                conn.execute(
                    "SELECT COUNT(*) FROM venues WHERE is_active = 1",
                    (),
                ).fetchone()[0]
                or 0
            )
            p = _pagination_model(page, per_page, total)
            
            venues = conn.execute(
                """
                SELECT v.*, u.name as manager_name
                FROM venues v
                JOIN users u ON u.email = v.manager_email
                WHERE v.is_active = 1
                ORDER BY v.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (p["per_page"], p["offset"]),
            ).fetchall()

        return render_template(
            "creator_venues.html",
            user_email=user["email"],
            venues=venues,
            pagination=p,
        )
    except Exception as e:
        print(f"Error loading venues: {e}")
        # Return empty venues list on error
        return render_template(
            "creator_venues.html",
            user_email=user["email"],
            venues=[],
            pagination={"pages": 1, "page": 1, "has_prev": False, "has_next": False},
        )


@app.get("/creator/events/<int:event_id>/stats")
def creator_event_stats(event_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        event = conn.execute(
            "SELECT * FROM events WHERE id = ? AND creator_email = ?",
            (event_id, user["email"]),
        ).fetchone()
        if not event:
            abort(404)
        totals = conn.execute(
            """
            SELECT
              COUNT(*) as booking_count,
              COALESCE(SUM(amount),0) as revenue
            FROM bookings
            WHERE event_id = ? AND status != 'canceled'
            """,
            (event_id,),
        ).fetchone()
        bookers = conn.execute(
            """
            SELECT customer_email, status, created_at
            FROM bookings
            WHERE event_id = ? AND status != 'canceled'
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (event_id,),
        ).fetchall()
    return render_template(
        "creator_event_stats.html",
        user_email=user["email"],
        event=event,
        totals=totals,
        bookers=bookers,
        public_url=request.url_root.rstrip("/") + f"/events/{event_id}",
    )


@app.get("/creator/analytics")
def creator_analytics_page():
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    
    with _db() as conn:
        # Get all creator's events with booking data
        events_with_revenue = conn.execute(
            """
            SELECT 
                e.id,
                e.title,
                e.event_date,
                e.venue,
                COALESCE(SUM(b.amount), 0) as revenue,
                COUNT(b.id) as booking_count,
                e.created_at
            FROM events e
            LEFT JOIN bookings b ON e.id = b.event_id AND b.status != 'canceled'
            WHERE e.creator_email = ?
            GROUP BY e.id
            ORDER BY e.created_at DESC
            LIMIT 12
            """,
            (user["email"],),
        ).fetchall()
        
        # Calculate totals
        total_revenue = sum(event["revenue"] for event in events_with_revenue)
        total_bookings = sum(event["booking_count"] for event in events_with_revenue)
        avg_price = total_revenue / len(events_with_revenue) if events_with_revenue else 0
        active_events = len([e for e in events_with_revenue if e["event_date"] >= datetime.now().strftime("%Y-%m-%d")])
        
        # Top performing events
        top_events = sorted(events_with_revenue, key=lambda x: x["revenue"], reverse=True)[:5]
        for event in top_events:
            event["performance_score"] = min(100, (event["revenue"] / 1000) * 10)  # Simple performance scoring
        
        # Chart data (last 6 months)
        chart_data = [event["revenue"] for event in events_with_revenue[:6]]
        chart_labels = [event["title"][:15] + "..." if len(event["title"]) > 15 else event["title"] for event in events_with_revenue[:6]]
        
        # Recent activity
        recent_activity = []
        for event in events_with_revenue[:3]:
            recent_activity.append({
                "time": event["created_at"][:10],
                "type": "revenue",
                "amount": event["revenue"],
                "description": f"Event '{event['title'][:20]}...' generated revenue"
            })
        
        # Calculate changes (mock data for demo)
        revenue_change = 15.2  # Mock 15.2% increase
        bookings_change = 8.7   # Mock 8.7% increase
        
        analytics = {
            "total_revenue": total_revenue,
            "total_bookings": total_bookings,
            "avg_price": round(avg_price, 2),
            "active_events": active_events,
            "revenue_change": revenue_change,
            "bookings_change": bookings_change,
            "top_events": top_events,
            "chart_data": chart_data,
            "chart_labels": chart_labels,
            "recent_activity": recent_activity
        }
    
    return render_template("creator_analytics.html", analytics=analytics, user_email=user["email"])


@app.get("/events/<int:event_id>")
def public_event_page(event_id: int):
    user = _current_user()
    with _db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not event:
            abort(404)
        conn.execute("UPDATE events SET views = COALESCE(views,0) + 1 WHERE id = ?", (event_id,))
        booking = None
        if user and user["role"] == "audience":
            booking = conn.execute(
                """
                SELECT id, status
                FROM bookings
                WHERE customer_email = ? AND event_id = ? AND status != 'canceled'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user["email"], event_id),
            ).fetchone()
    return render_template(
        "event_public.html",
        event=event,
        booking=booking,
        user=user,
    )


@app.post("/creator/events")
def creator_create_event():
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user

    title = _sanitize_string((request.form.get("title") or "").strip(), 200)
    event_date = (request.form.get("event_date") or "").strip()
    venue = _sanitize_string((request.form.get("venue") or "").strip(), 200)
    description = _sanitize_string((request.form.get("description") or "").strip(), 2000)

    # Comprehensive validation
    if not title or not event_date or not venue or not description:
        return redirect(url_for("creator_dashboard") + "?error=missing")
    
    # Validate title length
    if len(title) < 3 or len(title) > 200:
        return redirect(url_for("creator_dashboard") + "?error=title")
    
    # Validate date format and ensure it's not in the past
    if not _validate_date(event_date):
        return redirect(url_for("creator_dashboard") + "?error=date")
    
    # Validate venue and description lengths
    if len(venue) < 3 or len(venue) > 200:
        return redirect(url_for("creator_dashboard") + "?error=venue")
    
    if len(description) < 10 or len(description) > 2000:
        return redirect(url_for("creator_dashboard") + "?error=description")

    thumb = request.files.get("thumbnail")
    thumb_path = None
    if thumb and (thumb.filename or "").strip():
        raw = secure_filename(thumb.filename)
        ext = os.path.splitext(raw)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".webp"):
            return redirect(url_for("creator_dashboard") + "?error=thumb")
        fname = f"{uuid.uuid4().hex}{ext}"
        abs_path = os.path.join(UPLOAD_DIR, fname)
        try:
            thumb.save(abs_path)
            thumb_path = f"uploads/{fname}"
        except Exception as e:
            # Log the error and continue without thumbnail
            print(f"Error saving thumbnail: {e}")
            thumb_path = None

    with _db() as conn:
        conn.execute(
            "INSERT INTO events (creator_email, title, event_date, venue, description, thumbnail_path) VALUES (?, ?, ?, ?, ?, ?)",
            (user["email"], title, event_date, venue, description, thumb_path),
        )
    return redirect(url_for("creator_dashboard"))


@app.get("/customer")
def customer_dashboard():
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user

    page, per_page = _get_page_args(default_per_page=6)
    with _db() as conn:
        total = (conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] or 0)
        p = _pagination_model(page, per_page, total)
        events = conn.execute(
            "SELECT * FROM events ORDER BY event_date ASC LIMIT ? OFFSET ?",
            (p["per_page"], p["offset"]),
        ).fetchall()

        booked_event_ids = {
            r[0]
            for r in conn.execute(
                """
                SELECT event_id
                FROM bookings
                WHERE customer_email = ? AND status != 'canceled'
                """,
                (user["email"],),
            ).fetchall()
        }
    return render_template(
        "customer.html",
        user_email=user["email"],
        events=events,
        pagination=p,
        booked_event_ids=booked_event_ids,
    )


@app.post("/book/<int:event_id>")
def create_booking(event_id: int):
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if not event:
            abort(404)

        existing = conn.execute(
            """
            SELECT id
            FROM bookings
            WHERE customer_email = ? AND event_id = ? AND status != 'canceled'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user["email"], event_id),
        ).fetchone()
        if existing:
            return redirect(
                url_for("booking_confirmation_page", booking_id=int(existing["id"]))
            )

        amount = 0
        user_row = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (user["email"],),
        ).fetchone()
        customer_id = int(user_row["id"]) if user_row else None

        cur = conn.execute(
            """
            INSERT INTO bookings (customer_email, customer_id, event_id, amount, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["email"], customer_id, event_id, amount, "booked"),
        )
        booking_id = cur.lastrowid
    return redirect(url_for("booking_confirmation_page", booking_id=booking_id))


@app.get("/booking/<int:booking_id>/confirmation")
def booking_confirmation_page(booking_id: int):
    user = _require_login()
    if not isinstance(user, dict):
        return user

    with _db() as conn:
        booking = conn.execute(
            """
            SELECT b.*, e.title, e.event_date, e.venue, e.description
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE b.id = ? AND b.customer_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()

        if not booking:
            abort(404)

    return render_template("booking_confirmation.html", booking=booking, event=booking)


@app.get("/booking/<int:booking_id>/ticket")
def booking_ticket_page(booking_id: int):
    user = _require_login()
    if not isinstance(user, dict):
        return user

    with _db() as conn:
        booking = conn.execute(
            """
            SELECT b.*, e.title, e.event_date, e.venue, e.description
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE b.id = ? AND b.customer_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()

        if not booking:
            abort(404)

        # Check if payment is verified (for now, we'll assume all bookings are verified)
        # In the future, you might want to add a payment_status field to the bookings table
        # For now, all bookings can access their tickets directly

        # Create event object from the joined query result
        event_data = {
            'title': booking['title'],
            'event_date': booking['event_date'],
            'venue': booking['venue'],
            'description': booking['description']
        }
        
        return render_template("ticket.html", booking=booking, event=event_data)


@app.get("/payment/<int:booking_id>")
def payment_page(booking_id: int):
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        row = conn.execute(
            """
            SELECT b.*, e.title as event_title, e.event_date as event_date, e.venue as event_venue
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE b.id = ? AND b.customer_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()
    if not row:
        abort(404)
    return render_template("payment.html", booking=row, user_email=user["email"])


@app.post("/payment/<int:booking_id>")
def payment_submit(booking_id: int):
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM bookings WHERE id = ? AND customer_email = ?",
            (booking_id, user["email"]),
        ).fetchone()
        if not row:
            abort(404)
        if row["status"] == "paid":
            return redirect(url_for("bookings_page"))
        conn.execute(
            "UPDATE bookings SET status = ?, paid_at = datetime('now') WHERE id = ?",
            ("paid", booking_id),
        )
    return redirect(url_for("bookings_page"))


@app.get("/bookings")
def bookings_page():
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user

    page, per_page = _get_page_args(default_per_page=6)
    with _db() as conn:
        total = (
            conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE customer_email = ?",
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        p = _pagination_model(page, per_page, total)
        rows = conn.execute(
            """
            SELECT b.*, e.title as event_title, e.event_date as event_date, e.venue as event_venue
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE b.customer_email = ?
            ORDER BY b.created_at DESC
            LIMIT ? OFFSET ?
            """,
            (user["email"], p["per_page"], p["offset"]),
        ).fetchall()
    today = date.today()
    return render_template(
        "bookings.html",
        user_email=user["email"],
        bookings=rows,
        today=today,
        pagination=p,
    )


def _cancel_fee_percent(days_before: int) -> int | None:
    if days_before >= 3:
        return 5
    if days_before == 2:
        return 10
    if days_before == 1:
        return 15
    return None


@app.get("/venuehub/analytics")
def venuehub_analytics_page():
    user = _require_role("venue_manager")
    if not isinstance(user, dict):
        return user
    
    with _db() as conn:
        # Get all venues with booking data
        venues_with_revenue = conn.execute(
            """
            SELECT 
                v.id,
                v.name,
                v.city,
                v.capacity,
                v.price_per_day,
                COALESCE(SUM(vb.amount), 0) as revenue,
                COUNT(vb.id) as booking_count,
                COALESCE(AVG(vb.amount), 0) as avg_booking_amount,
                v.created_at
            FROM venues v
            LEFT JOIN venue_bookings vb ON v.id = vb.venue_id AND vb.status = 'approved'
            WHERE v.manager_email = ?
            GROUP BY v.id
            ORDER BY v.created_at DESC
            LIMIT 12
            """,
            (user["email"],),
        ).fetchall()
        
        # Calculate totals
        total_revenue = sum(venue["revenue"] for venue in venues_with_revenue)
        total_bookings = sum(venue["booking_count"] for venue in venues_with_revenue)
        avg_daily_rate = total_revenue / 30 if venues_with_revenue else 0  # Last 30 days average
        avg_booking_amount = sum(venue["avg_booking_amount"] for venue in venues_with_revenue) / len(venues_with_revenue) if venues_with_revenue else 0
        
        # Calculate occupancy (mock calculation for demo)
        total_capacity = sum(venue["capacity"] for venue in venues_with_revenue)
        estimated_booked_days = sum(venue["booking_count"] for venue in venues_with_revenue)
        occupancy_rate = (estimated_booked_days / (total_capacity * 30)) * 100 if total_capacity > 0 else 0
        occupancy_status = "Excellent" if occupancy_rate >= 70 else "Good" if occupancy_rate >= 50 else "Needs Improvement"
        
        # Top performing venues
        top_venues = sorted(venues_with_revenue, key=lambda x: x["revenue"], reverse=True)[:5]
        for venue in top_venues:
            venue["performance_score"] = min(100, (venue["revenue"] / 10000) * 10)
            venue["performance_grade"] = "A+" if venue["performance_score"] >= 90 else "A" if venue["performance_score"] >= 80 else "B" if venue["performance_score"] >= 70 else "C"
            venue["rating"] = venue["performance_score"] / 20  # Convert to 5-star scale
        
        # Chart data (last 6 months)
        chart_data = [venue["revenue"] for venue in venues_with_revenue[:6]]
        chart_labels = [venue["name"][:15] + "..." if len(venue["name"]) > 15 else venue["name"] for venue in venues_with_revenue[:6]]
        
        # Recent booking requests
        recent_requests = conn.execute(
            """
            SELECT 
                vb.id,
                vb.event_title,
                vb.requested_date,
                vb.amount,
                vb.status,
                v.name as venue_name
            FROM venue_bookings vb
            JOIN venues v ON v.id = vb.venue_id
            WHERE v.manager_email = ?
            ORDER BY vb.created_at DESC
            LIMIT 10
            """,
            (user["email"],),
        ).fetchall()
        
        # Format recent requests
        formatted_requests = []
        for req in recent_requests:
            status_class = "approved" if req["status"] == "approved" else "pending" if req["status"] == "pending" else "rejected"
            formatted_requests.append({
                "venue_name": req["venue_name"],
                "event_title": req["event_title"],
                "requested_date": req["requested_date"][:10],
                "amount": req["amount"],
                "status": req["status"].title(),
                "status_class": status_class
            })
        
        # Calculate changes (mock data for demo)
        revenue_change = 12.8  # Mock 12.8% increase
        bookings_change = 15.3  # Mock 15.3% increase
        
        analytics = {
            "total_revenue": total_revenue,
            "total_bookings": total_bookings,
            "avg_daily_rate": round(avg_daily_rate, 2),
            "occupancy_rate": round(occupancy_rate, 1),
            "occupancy_status": occupancy_status,
            "revenue_change": revenue_change,
            "bookings_change": bookings_change,
            "venues": venues_with_revenue,
            "top_venues": top_venues,
            "chart_data": chart_data,
            "chart_labels": chart_labels,
            "recent_requests": formatted_requests
        }
    
    return render_template("venuehub_analytics.html", analytics=analytics, user_email=user["email"])


@app.post("/bookings/<int:booking_id>/cancel")
def cancel_booking(booking_id: int):
    user = _require_role("audience")
    if not isinstance(user, dict):
        return user
    with _db() as conn:
        row = conn.execute(
            """
            SELECT b.*, e.event_date as event_date
            FROM bookings b
            JOIN events e ON e.id = b.event_id
            WHERE b.id = ? AND b.customer_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()
        if not row:
            abort(404)
        if row["status"] == "canceled":
            return redirect(url_for("bookings_page"))
        if row["status"] != "paid":
            conn.execute(
                "UPDATE bookings SET status = ?, canceled_at = datetime('now'), refund_amount = 0, refund_fee_percent = 0 WHERE id = ?",
                ("canceled", booking_id),
            )
            return redirect(url_for("bookings_page"))

        try:
            d = datetime.strptime(row["event_date"], "%Y-%m-%d").date()
        except ValueError:
            return redirect(url_for("bookings_page") + "?error=date")

        days_before = (d - date.today()).days
        fee = _cancel_fee_percent(days_before)
        if fee is None:
            return redirect(url_for("bookings_page") + "?error=nocancel")

        amount = int(row["amount"])
        refund = int(round(amount * (1 - (fee / 100))))
        conn.execute(
            "UPDATE bookings SET status = ?, canceled_at = datetime('now'), refund_amount = ?, refund_fee_percent = ? WHERE id = ?",
            ("canceled", refund, fee, booking_id),
        )
    return redirect(url_for("bookings_page"))


@app.post("/signup")
def signup():
    name = _sanitize_string((request.form.get("name") or "").strip(), 100)
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "").strip().lower()
    if role == "venue":
        role = "venue_manager"

    signup_redirect = url_for("signup_page")
    if role == "audience":
        signup_redirect = url_for("signup_audience_page")
    elif role == "creator":
        signup_redirect = url_for("signup_creator_page")
    elif role == "venue_manager":
        signup_redirect = url_for("signup_venue_page")

    if role not in ("audience", "creator", "venue_manager"):
        return redirect(url_for("signup_page") + "?error=role")
    if not name or not email or not password:
        return redirect(signup_redirect + "?error=missing")

    if not _validate_email(email):
        return redirect(signup_redirect + "?error=email")

    is_valid_password, password_error = _validate_password(password)
    if not is_valid_password:
        return redirect(signup_redirect + "?error=password")

    if len(name) < 2 or len(name) > 100:
        return redirect(signup_redirect + "?error=name")

    pw_hash = generate_password_hash(password)

    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (name, email, pw_hash, role),
            )
    except sqlite3.IntegrityError:
        return redirect(signup_redirect + "?error=exists")

    session["user_email"] = email
    session["user_role"] = role
    return redirect(url_for("login_page", role=role))


@app.post("/login")
def login():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "").strip().lower()
    if role == "venue":
        role = "venue_manager"
    if role not in ("audience", "creator", "venue_manager"):
        role = "audience"
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return redirect(url_for("login_page") + "?error=login&role=" + role)

    if row["role"] != role:
        return redirect(url_for("login_page") + "?error=role&role=" + role)

    session["user_email"] = email
    session["user_role"] = row["role"]
    return redirect(url_for("profile"))


@app.get("/profile")
def profile():
    user = _require_login()
    if not isinstance(user, dict):
        return user
    if user["role"] == "creator":
        return redirect(url_for("creator_dashboard"))
    elif user["role"] == "venue_manager":
        return redirect(url_for("venuehub_dashboard"))
    return redirect(url_for("customer_dashboard"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/venuehub")
def venuehub_dashboard():
    user = _require_login()
    if not isinstance(user, dict):
        return user
    
    page, per_page = _get_page_args(default_per_page=6)
    with _db() as conn:
        total = (
            conn.execute(
                "SELECT COUNT(*) FROM venues WHERE manager_email = ?",
                (user["email"],),
            ).fetchone()[0]
            or 0
        )
        p = _pagination_model(page, per_page, total)
        
        venues = conn.execute(
            """
            SELECT * FROM venues 
            WHERE manager_email = ? 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
            """,
            (user["email"], p["per_page"], p["offset"]),
        ).fetchall()
        
        booking_requests = conn.execute(
            """
            SELECT vb.*, v.name as venue_name
            FROM venue_bookings vb
            JOIN venues v ON v.id = vb.venue_id
            WHERE v.manager_email = ?
            ORDER BY vb.created_at DESC
            LIMIT 10
            """,
            (user["email"],),
        ).fetchall()
    
    return render_template(
        "venuehub.html",
        user_email=user["email"],
        venues=venues,
        pagination=p,
        booking_requests=booking_requests,
    )


@app.post("/venuehub/venues")
def venuehub_create_venue():
    user = _require_login()
    if not isinstance(user, dict):
        return user
    
    name = (request.form.get("name") or "").strip()
    city = (request.form.get("city") or "").strip()
    address = (request.form.get("address") or "").strip()
    capacity = request.form.get("capacity")
    price_per_day = request.form.get("price_per_day")
    price_per_hour = request.form.get("price_per_hour")
    amenities = request.form.getlist("amenities")
    description = (request.form.get("description") or "").strip()
    
    if not name or not city or not address or not capacity or not price_per_day or not price_per_hour or not description:
        return redirect(url_for("venuehub_dashboard") + "?error=missing")
    
    try:
        capacity = int(capacity)
        price_per_day = int(price_per_day)
        price_per_hour = int(price_per_hour)
    except ValueError:
        return redirect(url_for("venuehub_dashboard") + "?error=invalid")
    
    amenities_str = ",".join(amenities) if amenities else ""
    
    try:
        with _db() as conn:
            conn.execute(
                """
                INSERT INTO venues 
                (manager_email, name, city, address, capacity, price_per_day, price_per_hour, amenities, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user["email"], name, city, address, capacity, price_per_day, price_per_hour, amenities_str, description),
            )
    except sqlite3.IntegrityError as e:
        print(f"Database error creating venue: {e}")
        return redirect(url_for("venuehub_dashboard") + "?error=database")
    except Exception as e:
        print(f"Unexpected error creating venue: {e}")
        return redirect(url_for("venuehub_dashboard") + "?error=unknown")
    
    return redirect(url_for("venuehub_dashboard"))


@app.post("/venuehub/bookings/<int:booking_id>/approve")
def venuehub_approve_booking(booking_id: int):
    user = _require_login()
    if not isinstance(user, dict):
        return user
    
    with _db() as conn:
        booking = conn.execute(
            """
            SELECT vb.* FROM venue_bookings vb
            JOIN venues v ON v.id = vb.venue_id
            WHERE vb.id = ? AND v.manager_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()
        
        if not booking:
            abort(404)
        
        conn.execute(
            "UPDATE venue_bookings SET status = ?, updated_at = datetime('now') WHERE id = ?",
            ("approved", booking_id),
        )
    
    return redirect(url_for("venuehub_dashboard"))


@app.post("/venuehub/bookings/<int:booking_id>/reject")
def venuehub_reject_booking(booking_id: int):
    user = _require_login()
    if not isinstance(user, dict):
        return user
    
    with _db() as conn:
        booking = conn.execute(
            """
            SELECT vb.* FROM venue_bookings vb
            JOIN venues v ON v.id = vb.venue_id
            WHERE vb.id = ? AND v.manager_email = ?
            """,
            (booking_id, user["email"]),
        ).fetchone()
        
        if not booking:
            abort(404)
        
        conn.execute(
            "UPDATE venue_bookings SET status = ?, updated_at = datetime('now') WHERE id = ?",
            ("rejected", booking_id),
        )
    
    return redirect(url_for("venuehub_dashboard"))


@app.post("/creator/venues/<int:venue_id>/request")
def creator_request_venue(venue_id: int):
    user = _require_role("creator")
    if not isinstance(user, dict):
        return user
    
    event_title = (request.form.get("event_title") or "").strip()
    requested_date = (request.form.get("requested_date") or "").strip()
    
    if not event_title or not requested_date:
        return redirect(url_for("creator_venues_page") + "?error=missing")
    
    with _db() as conn:
        # Check if venue exists and is active
        venue = conn.execute(
            "SELECT * FROM venues WHERE id = ? AND is_active = 1",
            (venue_id,),
        ).fetchone()
        
        if not venue:
            abort(404)
        
        # Create booking request
        conn.execute(
            """
            INSERT INTO venue_bookings 
            (venue_id, event_title, creator_email, requested_date, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (venue_id, event_title, user["email"], requested_date, "pending"),
        )
    
    return redirect(url_for("creator_venues_page") + "?success=requested")


if __name__ == "__main__":
    # Initialize database
    _init_db()
    
    # Production-ready server configuration
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    if not is_production:
        print("Starting Spotly application in DEVELOPMENT mode...")
        print("Database initialized successfully")
        print("Available routes:")
        for rule in app.url_map.iter_rules():
            print(f"  {rule.methods} {rule.rule}")
        print("\nStarting Flask server on http://127.0.0.1:5000")
        print("Press Ctrl+C to stop the server")
        app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
    else:
        logger.info("Starting Spotly application in PRODUCTION mode...")
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False,
            use_reloader=False
        )
