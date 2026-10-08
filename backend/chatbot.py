from collections.abc import Iterator

try:
    from google import genai
    from google.genai import types
except Exception as e:
    raise RuntimeError(
        "Missing or misconfigured google-genai package. Install it with: \n"
        "pip install google-genai\n"
        f"Original error: {e}"
    )
import os
from dotenv import load_dotenv
from bemba_context import BEMBA_PAIRS, build_context

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SYSTEM_PROMPT = """You are ZamCyberAI, a friendly and intelligent bilingual
assistant that speaks both English and Bemba (Icibemba), the language spoken
in Zambia.

Core Rules:
1. Detect the language the user is writing in (English or Bemba).
2. Always reply in the SAME language the user used.
3. If asked to translate, translate accurately between English and Bemba.
4. Use the translation examples provided to give accurate Bemba responses.
5. If unsure of a Bemba word, be honest about it.
6. Be warm, helpful and culturally respectful of Zambian culture.
7. Always introduce yourself as ZamCyberAI when asked who you are.
8. Only discuss information technology, computers, programming, technology
   trends, cybersecurity, and closely related technology topics.
9. If a request is outside this scope, politely explain in the user's language
   that ZamCyberAI is a technology and cybersecurity education assistant, then
   offer a relevant technology topic it can help with.
10. Keep cybersecurity advice educational, ethical, and focused on defensive
    practices, safety, and awareness.
11. Keep every normal response concise, clear, and easy to scan. Give the
    essential answer first; use short paragraphs or a short list only when it
    improves clarity. Avoid unnecessary background, repetition, or long
    examples.
12. End every normal response by asking, in the same language as the user,
    whether they would like a more detailed explanation. Do not add this
    question to a security warning that tells the user to avoid a scam or
    malicious message."""


def _build_response_request(
    user_message: str,
    history: list,
    language: str = "english",
    topic: str | None = None,
    user_profile: dict | None = None,
) -> tuple[list, str]:
    """Build the Gemini conversation and instructions for a chat response."""

    dataset_context = build_context(user_message, BEMBA_PAIRS)

    if language == "bemba":
        lang_instruction = "The user has selected Bemba. Respond in Bemba (Icibemba) as much as possible."
    else:
        lang_instruction = "The user has selected English. Respond in English."

    profile_context = ""
    if user_profile:
        experience = user_profile.get("experience_level", "beginner")
        profile_context += f"Learner profile: language={user_profile.get('preferred_language', language)}, level={experience}, goal={user_profile.get('learning_goal', 'cyber awareness')}."
        if experience == "beginner":
            profile_context += " Explain simply, use brief examples, define jargon, and keep the response easy to follow."
        elif experience == "intermediate":
            profile_context += " Explain with moderate detail and practical examples."
        else:
            profile_context += " Provide deeper technical detail and risk trade-offs when relevant."

    if topic:
        profile_context += f" Current topic focus: {topic}. Keep the answer tied to this topic and suggest one next step or example when useful."

    full_system = SYSTEM_PROMPT
    full_system += f"\n\nLanguage Instruction:\n{lang_instruction}"
    if profile_context:
        full_system += f"\n\nLearning Context:\n{profile_context}"

    if dataset_context:
        full_system += f"\n\nBemba Language Context:\n{dataset_context}"

    # ── Build Gemini-style conversation contents ──
    contents = []
    for msg in history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(
            types.Content(role=role, parts=[types.Part.from_text(text=msg["content"])])
        )
    contents.append(
        types.Content(role="user", parts=[types.Part.from_text(text=user_message)])
    )

    return contents, full_system


def get_response_stream(
    user_message: str,
    history: list,
    language: str = "english",
    topic: str | None = None,
    user_profile: dict | None = None,
) -> Iterator[str]:
    """Yield generated response text as Gemini produces it."""
    contents, full_system = _build_response_request(
        user_message, history, language, topic, user_profile
    )
    for response in client.models.generate_content_stream(
        model="gemini-2.5-flash",
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=full_system
        )
    ):
        if response.text:
            yield response.text


def get_response(
    user_message: str,
    history: list,
    language: str = "english",
    topic: str | None = None,
    user_profile: dict | None = None,
) -> str:
    """Get a complete response for callers that do not use streaming."""
    contents, full_system = _build_response_request(
        user_message, history, language, topic, user_profile
    )
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=full_system
        )
    )
    return response.text


def improve_response(user_message: str, previous_response: str, language: str = "english") -> str:
    """Generate a clearer replacement after the user marks a reply unhelpful."""
    language_instruction = (
        "Respond in Bemba (Icibemba) as much as possible."
        if language == "bemba"
        else "Respond in English."
    )
    revision_request = f"""The user marked the previous answer as unhelpful.
Write a better replacement that answers their original question. Be concise,
clear, accurate, and practical. Do not mention the rating, the previous answer,
or this instruction. End by asking whether they would like a deeper explanation.

Original question:
{user_message}

Previous answer:
{previous_response}"""
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=[types.Content(role="user", parts=[types.Part.from_text(text=revision_request)])],
        config=types.GenerateContentConfig(
            system_instruction=f"{SYSTEM_PROMPT}\n\nLanguage Instruction:\n{language_instruction}"
        )
    )
    return response.text
