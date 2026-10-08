import sqlite3
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

DATABASE = "zamcyberai.db"
PASSWORD_ITERATIONS = 310_000
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Migrate databases created before login lockouts were added.
    user_columns = {row[1] for row in cursor.execute("PRAGMA table_info(users)")}
    if "failed_login_attempts" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
    if "lockout_until" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN lockout_until TEXT")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT DEFAULT 'New Chat',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS learning_profiles (
            user_id INTEGER PRIMARY KEY,
            preferred_language TEXT NOT NULL DEFAULT 'english',
            experience_level TEXT NOT NULL DEFAULT 'beginner',
            learning_goal TEXT NOT NULL DEFAULT 'cyber awareness',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS topic_mastery (
            user_id INTEGER NOT NULL,
            topic TEXT NOT NULL,
            mastery_score INTEGER NOT NULL DEFAULT 0,
            lessons_completed INTEGER NOT NULL DEFAULT 0,
            last_reviewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, topic),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            language TEXT DEFAULT 'english',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_feedback (
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            reaction TEXT NOT NULL CHECK (reaction IN ('up', 'down')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES messages (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Use a salted, deliberately slow hash for stored passwords."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> tuple[bool, bool]:
    """Return whether a password matches and whether its hash needs upgrading."""
    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
            calculated = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
            )
            return hmac.compare_digest(calculated.hex(), digest_hex), False
        except (ValueError, TypeError):
            return False, False

    # Support existing accounts once, then replace the old unsalted SHA-256 hash.
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, stored_hash), True


def register_user(username: str, email: str, password: str) -> dict:
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        hashed = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed)
        )
        conn.commit()
        return {"success": True, "message": "Account created successfully!"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Username or email already exists."}
    finally:
        if conn:
            conn.close()


def login_user(email: str, password: str) -> dict:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password, failed_login_attempts, lockout_until FROM users WHERE email = ?",
        (email,)
    )
    user = cursor.fetchone()
    if not user:
        conn.close()
        return {"success": False, "message": "Invalid email or password."}

    user_id, username, stored_hash, failed_attempts, lockout_until = user
    now = datetime.now(timezone.utc)
    if lockout_until:
        try:
            lockout_time = datetime.fromisoformat(lockout_until)
            if lockout_time.tzinfo is None:
                lockout_time = lockout_time.replace(tzinfo=timezone.utc)
            if lockout_time > now:
                remaining = max(1, int((lockout_time - now).total_seconds() / 60) + 1)
                conn.close()
                return {"success": False, "message": f"Account temporarily locked. Try again in {remaining} minute(s)."}
        except ValueError:
            pass

    password_matches, needs_upgrade = verify_password(password, stored_hash)
    if password_matches:
        upgraded_hash = hash_password(password) if needs_upgrade else stored_hash
        cursor.execute(
            "UPDATE users SET password = ?, failed_login_attempts = 0, lockout_until = NULL WHERE id = ?",
            (upgraded_hash, user_id),
        )
        conn.commit()
        conn.close()
        return {"success": True, "user_id": user_id, "username": username}

    failed_attempts += 1
    lockout_time = None
    if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        lockout_time = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        failed_attempts = 0
    cursor.execute(
        "UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?",
        (failed_attempts, lockout_time, user_id),
    )
    conn.commit()
    conn.close()
    if lockout_time:
        return {"success": False, "message": "Account temporarily locked. Try again in 15 minutes."}
    return {"success": False, "message": "Invalid email or password."}


# ─────────────────────────────────────────
# CONVERSATIONS
# ─────────────────────────────────────────

def create_conversation(user_id: int, title: str = "New Chat") -> int:
    """Create a new conversation and return its id."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO conversations (user_id, title) VALUES (?, ?)",
        (user_id, title)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_conversations(user_id: int) -> list:
    """Get all conversations for a user, most recent first."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            c.id,
            COALESCE(
                NULLIF(c.title, 'New Chat'),
                (
                    SELECT CASE
                        WHEN LENGTH(m.content) > 40 THEN SUBSTR(m.content, 1, 40) || '...'
                        ELSE m.content
                    END
                    FROM messages m
                    WHERE m.conversation_id = c.id AND m.role = 'user'
                    ORDER BY m.id ASC
                    LIMIT 1
                ),
                'New Chat'
            ) AS title,
            c.created_at
        FROM conversations c
        WHERE c.user_id = ?
        ORDER BY c.id DESC
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "created_at": r[2]} for r in rows]


def rename_conversation(conversation_id: int, title: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE conversations SET title = ? WHERE id = ?",
        (title, conversation_id)
    )
    conn.commit()
    conn.close()


def delete_conversation(conversation_id: int):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM message_feedback WHERE message_id IN "
        "(SELECT id FROM messages WHERE conversation_id = ?)",
        (conversation_id,)
    )
    cursor.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
    cursor.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    conn.commit()
    conn.close()


def ensure_learning_profile(
    user_id: int,
    preferred_language: str = "english",
    experience_level: str = "beginner",
    learning_goal: str = "cyber awareness",
) -> dict:
    """Create or update the user's learning profile with simple defaults."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT preferred_language, experience_level, learning_goal FROM learning_profiles WHERE user_id = ?",
        (user_id,),
    )
    row = cursor.fetchone()

    if row is None:
        cursor.execute(
            "INSERT INTO learning_profiles (user_id, preferred_language, experience_level, learning_goal) VALUES (?, ?, ?, ?)",
            (user_id, preferred_language, experience_level, learning_goal),
        )
        conn.commit()
        result = {"preferred_language": preferred_language, "experience_level": experience_level, "learning_goal": learning_goal}
    else:
        current_language, current_level, current_goal = row
        updated_language = preferred_language if preferred_language in {"english", "bemba"} else current_language
        updated_level = experience_level if experience_level in {"beginner", "intermediate", "advanced"} else current_level
        updated_goal = learning_goal or current_goal
        cursor.execute(
            "UPDATE learning_profiles SET preferred_language = ?, experience_level = ?, learning_goal = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (updated_language, updated_level, updated_goal, user_id),
        )
        conn.commit()
        result = {"preferred_language": updated_language, "experience_level": updated_level, "learning_goal": updated_goal}

    conn.close()
    return result


def get_learning_profile(user_id: int) -> dict:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT preferred_language, experience_level, learning_goal FROM learning_profiles WHERE user_id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return ensure_learning_profile(user_id)
    return {"preferred_language": row[0], "experience_level": row[1], "learning_goal": row[2]}


def update_topic_mastery(user_id: int, topic: str, gain: int = 5, completed: bool = False) -> dict:
    """Store a lightweight topic mastery score for the learner."""
    if not topic or not topic.strip():
        return {"topic": None, "mastery_score": 0, "lessons_completed": 0}

    topic_name = topic.strip()
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT mastery_score, lessons_completed FROM topic_mastery WHERE user_id = ? AND topic = ?",
        (user_id, topic_name),
    )
    row = cursor.fetchone()
    current_score = row[0] if row else 0
    current_lessons = row[1] if row else 0
    updated_score = max(0, min(100, current_score + int(gain)))
    updated_lessons = current_lessons + (1 if completed else 0)

    if row is None:
        cursor.execute(
            "INSERT INTO topic_mastery (user_id, topic, mastery_score, lessons_completed) VALUES (?, ?, ?, ?)",
            (user_id, topic_name, updated_score, updated_lessons),
        )
    else:
        cursor.execute(
            "UPDATE topic_mastery SET mastery_score = ?, lessons_completed = ?, last_reviewed_at = CURRENT_TIMESTAMP WHERE user_id = ? AND topic = ?",
            (updated_score, updated_lessons, user_id, topic_name),
        )
    conn.commit()
    conn.close()
    return {"topic": topic_name, "mastery_score": updated_score, "lessons_completed": updated_lessons}


def get_topic_mastery(user_id: int) -> dict:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT topic, mastery_score, lessons_completed FROM topic_mastery WHERE user_id = ? ORDER BY topic ASC",
        (user_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return {topic: {"mastery_score": score, "lessons_completed": lessons} for topic, score, lessons in rows}


def verify_conversation_owner(conversation_id: int, user_id: int) -> bool:
    """Security check: make sure this conversation belongs to this user."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
        (conversation_id, user_id)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


# ─────────────────────────────────────────
# MESSAGES
# ─────────────────────────────────────────

def save_message(conversation_id: int, role: str, content: str, language: str = "english"):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (conversation_id, role, content, language) VALUES (?, ?, ?, ?)",
        (conversation_id, role, content, language)
    )
    conn.commit()
    message_id = cursor.lastrowid
    conn.close()
    return message_id


def get_messages(conversation_id: int) -> list:
    """Get all messages for a conversation, oldest first."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC",
        (conversation_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": message_id, "role": role, "content": content} for message_id, role, content in rows]


def save_message_feedback(message_id: int, user_id: int, reaction: str) -> dict | None:
    """Save a reaction and return the assistant response plus its user prompt."""
    if reaction not in {"up", "down"}:
        return None

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            m.content,
            m.language,
            (
                SELECT previous.content
                FROM messages AS previous
                WHERE previous.conversation_id = m.conversation_id
                  AND previous.role = 'user'
                  AND previous.id < m.id
                ORDER BY previous.id DESC
                LIMIT 1
            )
        FROM messages AS m
        JOIN conversations AS c ON c.id = m.conversation_id
        WHERE m.id = ? AND m.role = 'assistant' AND c.user_id = ?
        """,
        (message_id, user_id),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    cursor.execute(
        """
        INSERT INTO message_feedback (message_id, user_id, reaction)
        VALUES (?, ?, ?)
        ON CONFLICT(message_id, user_id) DO UPDATE SET
            reaction = excluded.reaction,
            updated_at = CURRENT_TIMESTAMP
        """,
        (message_id, user_id, reaction),
    )
    conn.commit()
    conn.close()
    return {"assistant_response": row[0], "language": row[1], "user_message": row[2] or ""}
