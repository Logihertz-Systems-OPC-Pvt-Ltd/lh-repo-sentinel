"""Shannon entropy calculation and high-entropy token detection."""

from __future__ import annotations

import collections
import math
import re

# Candidate token pattern: contiguous alphanumeric and common base64/hex characters
CANDIDATE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_\-\.]{16,}")


def calculate_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a given string in bits per symbol.

    Formula: H(X) = - sum(P(x_i) * log2(P(x_i)))

    Args:
        data: The input string to evaluate.

    Returns:
        Shannon entropy as a float (0.0 for empty or uniform strings).
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies = collections.Counter(data)
    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# Alias for calculate_entropy
shannon_entropy = calculate_entropy


def _is_probable_code_identifier(token: str) -> bool:
    """Check if token is likely a benign code identifier (e.g., CamelCase class name).

    Benign identifiers typically consist exclusively of alphabetic letters without digits,
    or follow standard snake_case naming without mixed numbers/symbols.
    """
    # Pure alphabetic tokens without digits or special symbols are usually identifiers
    if token.isalpha():
        return True

    # Tokens with multiple consecutive hyphens or slashes are likely paths or separators
    if "//" in token or "--" in token:
        return True

    return False


def find_high_entropy_tokens(
    text: str,
    threshold: float = 4.5,
    min_length: int = 16,
) -> list[tuple[str, float]]:
    """Scan text for candidate secret tokens exceeding the entropy threshold.

    Args:
        text: The source text or line of code to analyze.
        threshold: Minimum Shannon entropy to trigger a finding (default: 4.5).
        min_length: Minimum character length for candidate tokens (default: 16).

    Returns:
        A list of tuples containing (token_string, entropy_value).
    """
    if not text:
        return []

    results: list[tuple[str, float]] = []
    seen: set[str] = set()

    for match in CANDIDATE_TOKEN_PATTERN.finditer(text):
        token = match.group(0).strip(".-_")
        if len(token) < min_length or token in seen:
            continue

        if _is_probable_code_identifier(token):
            continue

        entropy = calculate_entropy(token)
        if entropy >= threshold:
            seen.add(token)
            results.append((token, entropy))

    return results
