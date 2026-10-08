import csv
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "bigc-data"
DATA_FILES = ("train.tsv", "valid.tsv", "test.tsv")
TOKEN_PATTERN = re.compile(r"[\w']+", re.UNICODE)


def _load_tsv(filepath: Path) -> list[tuple[str, str]]:
    """Load (English, Bemba) pairs from the BIGC sentence/translation columns."""
    pairs = []
    with filepath.open(encoding="utf-8", newline="") as file:
        reader = csv.reader(file, delimiter="\t")
        first_row = next(reader, None)
        if not first_row:
            return pairs

        has_bigc_header = "sentence" in first_row and "translation" in first_row
        if has_bigc_header:
            bemba_index = first_row.index("sentence")
            english_index = first_row.index("translation")
            rows = reader
        else:
            # Support compatible files that omit the BIGC header row.
            bemba_index = 5
            english_index = 6
            rows = iter([first_row], reader)

        for row in rows:
            if len(row) <= max(bemba_index, english_index):
                continue
            bemba = row[bemba_index].strip()
            english = row[english_index].strip()
            if english and bemba:
                pairs.append((english, bemba))
    return pairs


def load_dataset() -> list[tuple[str, str]]:
    """Load and deduplicate all available BIGC English-Bemba pairs."""
    pairs = []
    seen = set()
    for filename in DATA_FILES:
        filepath = DATA_DIR / filename
        if not filepath.exists():
            continue
        for pair in _load_tsv(filepath):
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
    return pairs


def _tokens(value: str) -> set[str]:
    return {token.lower() for token in TOKEN_PATTERN.findall(value)}


def find_relevant_pairs(user_message: str, pairs: list, max_results: int = 5) -> list:
    """
    Search the dataset for pairs relevant to the user's message.
    Returns a list of (english, bemba) matches.
    """
    user_words = _tokens(user_message)
    scored = []

    for english, bemba in pairs:
        english_words = _tokens(english)
        bemba_words = _tokens(bemba)
        # Search both sides so Bemba questions can retrieve Bemba guidance.
        score = max(
            len(user_words & english_words),
            len(user_words & bemba_words),
        )
        if score > 0:
            scored.append((score, english, bemba))

    # Sort by highest score first
    scored.sort(reverse=True, key=lambda x: x[0])

    # Return top matches
    return [(e, b) for _, e, b in scored[:max_results]]


def build_context(user_message: str, pairs: list) -> str:
    """
    Build a context string from relevant dataset pairs
    to inject into the Claude system prompt.
    """
    relevant = find_relevant_pairs(user_message, pairs)

    if not relevant:
        return ""

    context = (
        "Use these relevant English-Bemba translation examples as language "
        "guidance. Preserve the user's meaning, do not invent translations, "
        "and do not treat the examples as cybersecurity facts:\n\n"
    )
    for english, bemba in relevant:
        context += f"  English : {english}\n"
        context += f"  Bemba   : {bemba}\n\n"

    return context


# ── Load dataset once when module is imported ──
BEMBA_PAIRS = load_dataset()