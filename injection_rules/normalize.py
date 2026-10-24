import re
from urllib.parse import unquote_plus

_SQL_INLINE_COMMENT = re.compile(r"/\*.*?\*/")
_WHITESPACE = re.compile(r"\s+")


def normalize(uri):
    if not uri:
        return ""
    text = str(uri)
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = text.lower()
    text = _SQL_INLINE_COMMENT.sub(" ", text)
    text = _WHITESPACE.sub(" ", text)
    return text.strip()
