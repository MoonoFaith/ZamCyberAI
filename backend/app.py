from flask import Flask, Response, request, jsonify, session, stream_with_context
from datetime import timedelta
import json
try:
    from flask_cors import CORS
except Exception:
    # Fallback when flask_cors is not installed: provide a no-op CORS
    def CORS(app, **kwargs):
        # minimal fallback: do nothing
        print("Warning: flask_cors not installed; CORS disabled")
        return None
from database import (
    init_db, register_user, login_user,
    create_conversation, get_conversations,
    delete_conversation, verify_conversation_owner,
    save_message, get_messages, save_message_feedback,
    ensure_learning_profile, get_learning_profile,
    update_topic_mastery, get_topic_mastery
)
from chatbot import get_response, get_response_stream, improve_response
from threat_analysis import analyze_submission, format_security_alert
import os
import re
from dotenv import load_dotenv

load_dotenv()

app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), "..", "frontend"),
    static_url_path="",
)
CORS(app, supports_credentials=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", os.urandom(32)),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

init_db()


@app.route("/")
def home():
    return app.send_static_file("login.html")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

MAX_USERNAME_LENGTH = 50
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
MAX_CHAT_MESSAGE_LENGTH = 4_000
MAX_ANALYSIS_LENGTH = 10_000
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}$")


def json_body() -> dict | None:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def text_value(data: dict, field: str, maximum: int) -> str | None:
    value = data.get(field)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and len(value) <= maximum else None


def positive_id(value) -> int | None:
    try:
        result = int(value)
        return result if result > 0 else None
    except (TypeError, ValueError):
        return None


def authenticated_user_id() -> int | None:
    """Read identity only from Flask's signed, HTTP-only session cookie."""
    return positive_id(session.get("user_id"))


def signup_error(username: str, email: str, password: str) -> str | None:
    if not re.fullmatch(r"[\w .'-]{2,50}", username, flags=re.UNICODE):
        return "Name must be 2–50 characters and contain only letters, numbers, spaces, underscores, apostrophes, hyphens, or periods."
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > MAX_EMAIL_LENGTH:
        return "Enter a valid email address."
    if len(password) < 8 or len(password) > MAX_PASSWORD_LENGTH:
        return "Password must be 8–128 characters."
    if (
        not re.search(r"[a-z]", password)
        or not re.search(r"[A-Z]", password)
        or not re.search(r"\d", password)
        or not re.search(r"[^A-Za-z0-9]", password)
    ):
        return "Password must include an uppercase letter, lowercase letter, number, and special character."
    return None


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request is too large."}), 413

# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────

@app.route("/signup", methods=["POST"])
def signup():
    data = json_body()
    if not data:
        return jsonify({"success": False, "message": "Send a valid JSON request."}), 400
    username = text_value(data, "username", MAX_USERNAME_LENGTH)
    email = text_value(data, "email", MAX_EMAIL_LENGTH)
    password = text_value(data, "password", MAX_PASSWORD_LENGTH)

    if not username or not email or not password:
        return jsonify({"success": False, "message": "All fields are required and must be within the allowed length."}), 400

    validation_error = signup_error(username, email, password)
    if validation_error:
        return jsonify({"success": False, "message": validation_error}), 400

    result = register_user(username, email, password)
    return jsonify(result)


@app.route("/login", methods=["POST"])
def login():
    data = json_body()
    if not data:
        return jsonify({"success": False, "message": "Send a valid JSON request."}), 400
    email = text_value(data, "email", MAX_EMAIL_LENGTH)
    password = text_value(data, "password", MAX_PASSWORD_LENGTH)

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    result = login_user(email, password)
    if result.get("success"):
        session.clear()
        session.permanent = True
        session["user_id"] = result["user_id"]
    return jsonify(result)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully."})


@app.route("/profile", methods=["GET", "POST"])
def learning_profile():
    user_id = authenticated_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    if request.method == "POST":
        data = json_body() or {}
        profile = ensure_learning_profile(
            user_id,
            preferred_language=data.get("preferred_language", "english"),
            experience_level=data.get("experience_level", "beginner"),
            learning_goal=data.get("learning_goal", "cyber awareness"),
        )
        return jsonify({"profile": profile})

    profile = get_learning_profile(user_id)
    return jsonify({"profile": profile, "topic_mastery": get_topic_mastery(user_id)})


# ─────────────────────────────────────────
# CONVERSATION ROUTES
# ─────────────────────────────────────────

@app.route("/conversations", methods=["GET"])
def list_conversations():
    user_id = authenticated_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    conversations = get_conversations(user_id)
    return jsonify({"conversations": conversations})


@app.route("/conversations", methods=["POST"])
def new_conversation():
    user_id = authenticated_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    conv_id = create_conversation(user_id, "New Chat")
    return jsonify({"success": True, "conversation_id": conv_id})


@app.route("/conversations/<int:conversation_id>/messages", methods=["GET"])
def conversation_messages(conversation_id):
    user_id = authenticated_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    if not verify_conversation_owner(conversation_id, user_id):
        return jsonify({"error": "Conversation not found."}), 404

    messages = get_messages(conversation_id)
    return jsonify({"messages": messages})


@app.route("/conversations/<int:conversation_id>", methods=["DELETE"])
def remove_conversation(conversation_id):
    user_id = authenticated_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in."}), 401

    if not verify_conversation_owner(conversation_id, user_id):
        return jsonify({"error": "Conversation not found."}), 404

    delete_conversation(conversation_id)
    return jsonify({"success": True})


# ─────────────────────────────────────────
# CHAT ROUTE
# ─────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze pasted message/email/link content without saving it to a chat."""
    data = json_body() or {}
    message = text_value(data, "message", MAX_ANALYSIS_LENGTH)
    if not message:
        return jsonify({"error": "Provide a message of up to 10,000 characters."}), 400
    return jsonify({"analysis": analyze_submission(message)})


@app.route("/feedback", methods=["POST"])
def feedback():
    """Store a reaction; a down-vote returns a clearer replacement when safe."""
    data = json_body() or {}
    user_id = authenticated_user_id()
    message_id = positive_id(data.get("message_id"))
    reaction = data.get("reaction")
    if not user_id or not message_id or not isinstance(reaction, str) or reaction not in {"up", "down"}:
        return jsonify({"error": "A user, assistant message, and valid reaction are required."}), 400

    context = save_message_feedback(message_id, user_id, reaction)
    if not context:
        return jsonify({"error": "Assistant message not found."}), 404

    if reaction != "down":
        return jsonify({"success": True})

    # Do not turn a malware or scam warning into a conversational response.
    if analyze_submission(context["user_message"])["verdict"] in {"scam", "malicious"}:
        return jsonify({"success": True, "improved_response": None})

    try:
        revised = improve_response(
            context["user_message"], context["assistant_response"], context["language"]
        )
    except Exception:
        return jsonify({"success": True, "improvement_error": "Could not generate a revised response."})
    return jsonify({"success": True, "improved_response": revised})


def prepare_chat_request(data):
    if not data:
        return None, (jsonify({"error": "Send a valid JSON request."}), 400)
    user_message = text_value(data, "message", MAX_CHAT_MESSAGE_LENGTH)
    language = data.get("language", "english")
    topic = data.get("topic")
    raw_conversation_id = data.get("conversation_id")
    conversation_id = positive_id(raw_conversation_id) if raw_conversation_id else None
    user_id = authenticated_user_id()
    if not isinstance(language, str) or language not in {"english", "bemba"}:
        return None, (jsonify({"error": "Unsupported language."}), 400)

    if not user_id:
        return None, (jsonify({"error": "Not logged in."}), 401)

    if not user_message:
        return None, (jsonify({"error": "Provide a message of up to 4,000 characters."}), 400)

    if raw_conversation_id and not conversation_id:
        return None, (jsonify({"error": "Invalid conversation."}), 400)
    if conversation_id and not verify_conversation_owner(conversation_id, user_id):
        return None, (jsonify({"error": "Conversation not found."}), 404)

    profile = ensure_learning_profile(user_id, preferred_language=language)
    selected_topic = topic.strip() if isinstance(topic, str) and topic.strip() else None
    if selected_topic:
        update_topic_mastery(user_id, selected_topic, gain=5)

    if not conversation_id:
        title = user_message[:40] + ("..." if len(user_message) > 40 else "")
        conversation_id = create_conversation(user_id, title)

    history = get_messages(conversation_id)
    save_message(conversation_id, "user", user_message, language)
    assessment = analyze_submission(user_message)
    return {
        "user_message": user_message,
        "language": language,
        "selected_topic": selected_topic,
        "conversation_id": conversation_id,
        "history": history,
        "assessment": assessment,
        "profile": profile,
    }, None


def create_chat_reply(prepared):
    assessment = prepared["assessment"]
    if assessment["verdict"] in {"scam", "malicious"}:
        return format_security_alert(assessment)
    return get_response(
        prepared["user_message"],
        prepared["history"],
        prepared["language"],
        topic=prepared["selected_topic"],
        user_profile=prepared["profile"],
    )


def chat_result(prepared, reply):
    assistant_message_id = save_message(
        prepared["conversation_id"], "assistant", reply, prepared["language"]
    )
    return jsonify({
        "reply": reply,
        "analysis": prepared["assessment"],
        "conversation_id": prepared["conversation_id"],
        "assistant_message_id": assistant_message_id,
        "profile": prepared["profile"],
        "topic_mastery": get_topic_mastery(authenticated_user_id()),
    })


@app.route("/chat", methods=["POST"])
def chat():
    prepared, error_response = prepare_chat_request(json_body())
    if error_response:
        return error_response

    return chat_result(prepared, create_chat_reply(prepared))


@app.route("/chat/stream", methods=["POST"])
def chat_stream():
    prepared, error_response = prepare_chat_request(json_body())
    if error_response:
        return error_response

    def event(payload):
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def generate():
        try:
            yield event({
                "type": "start",
                "conversation_id": prepared["conversation_id"],
            })
            assessment = prepared["assessment"]
            if assessment["verdict"] in {"scam", "malicious"}:
                reply = format_security_alert(assessment)
                yield event({"type": "chunk", "text": reply})
            else:
                reply_parts = []
                for part in get_response_stream(
                    prepared["user_message"],
                    prepared["history"],
                    prepared["language"],
                    topic=prepared["selected_topic"],
                    user_profile=prepared["profile"],
                ):
                    reply_parts.append(part)
                    yield event({"type": "chunk", "text": part})
                reply = "".join(reply_parts).strip()
                if not reply:
                    raise RuntimeError("The model returned an empty response.")

            result = chat_result(prepared, reply).get_json()
            yield event({"type": "done", **result})
        except Exception:
            app.logger.exception("Could not stream chat response")
            yield event({
                "type": "error",
                "error": "Could not generate a response right now. Please try again.",
            })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────
# RUN SERVER
# ─────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "").lower() == "true", port=5000)
