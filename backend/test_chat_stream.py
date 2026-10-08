import json
from types import SimpleNamespace


def test_chatbot_yields_gemini_stream_chunks(monkeypatch):
    import chatbot

    monkeypatch.setattr(
        chatbot,
        "client",
        SimpleNamespace(
            models=SimpleNamespace(
                generate_content_stream=lambda **_kwargs: iter(
                    (SimpleNamespace(text="First "), SimpleNamespace(text="second."))
                )
            )
        ),
    )

    assert list(chatbot.get_response_stream("Question?", [])) == ["First ", "second."]


def test_streaming_chat_returns_chunks_and_saves_assistant_reply(tmp_path, monkeypatch):
    import database

    monkeypatch.setattr(database, "DATABASE", str(tmp_path / "chat-stream.db"))
    database.init_db()

    import app as app_module

    user = database.register_user("Stream Tester", "stream@example.com", "SafePassword1!")
    assert user["success"] is True
    user_id = database.login_user("stream@example.com", "SafePassword1!")["user_id"]
    previous_conversation_id = database.create_conversation(user_id, "Earlier chat")
    database.save_message(previous_conversation_id, "user", "Older question", "english")
    database.save_message(previous_conversation_id, "assistant", "Older answer", "english")

    monkeypatch.setattr(
        app_module,
        "get_response_stream",
        lambda *_args, **_kwargs: iter(("A streamed ", "reply.")),
    )

    with app_module.app.test_client() as client:
        with client.session_transaction() as session:
            session["user_id"] = user_id

        response = client.post(
            "/chat/stream",
            json={"message": "Explain strong passwords.", "language": "english"},
        )

    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    events = [
        json.loads(block.removeprefix("data: ").strip())
        for block in response.get_data(as_text=True).strip().split("\n\n")
    ]
    assert events[0] == {
        "type": "start",
        "conversation_id": events[-1]["conversation_id"],
    }
    assert events[0]["conversation_id"] != previous_conversation_id
    assert [event["text"] for event in events[1:3]] == ["A streamed ", "reply."]
    assert events[-1]["type"] == "done"
    assert events[-1]["reply"] == "A streamed reply."

    messages = database.get_messages(events[-1]["conversation_id"])
    assert messages[-1]["role"] == "assistant"
    assert messages[-1]["content"] == events[-1]["reply"]
    assert len(database.get_messages(previous_conversation_id)) == 2
