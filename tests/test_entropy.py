# lh-sentinel: ignore-file
"""Unit tests for Shannon entropy calculation and candidate token extraction."""

import math

from lh_repo_sentinel.entropy import (
    calculate_entropy,
    find_high_entropy_tokens,
    shannon_entropy,
)


def test_entropy_empty_and_uniform():
    """Verify entropy for empty and uniform character sequences is 0.0."""
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaaaa") == 0.0
    assert shannon_entropy("1111111111") == 0.0


def test_entropy_mathematical_precision():
    """Test entropy against mathematically exact values for uniform distributions."""
    # 2 symbols in equal proportions: H = 1.0 bit
    binary_seq = "ab" * 50
    assert math.isclose(calculate_entropy(binary_seq), 1.0, rel_tol=1e-5)

    # 4 symbols in equal proportions: H = 2.0 bits
    quad_seq = "abcd" * 25
    assert math.isclose(calculate_entropy(quad_seq), 2.0, rel_tol=1e-5)

    # 16 symbols in equal proportions: H = 4.0 bits
    hex_seq = "0123456789abcdef" * 10
    assert math.isclose(calculate_entropy(hex_seq), 4.0, rel_tol=1e-5)


def test_find_high_entropy_tokens():
    """Verify detection of high entropy tokens and filtering of identifiers."""
    # High entropy base64 token
    random_token = "K9zmQ8xL2vW5yR1aBcDeFgHiJkLmNoPq"
    clean_line = f'api_key = "{random_token}"'
    tokens = find_high_entropy_tokens(clean_line, threshold=4.0, min_length=16)

    assert len(tokens) >= 1
    found_tokens = [t[0] for t in tokens]
    assert any(random_token in t or t in random_token for t in found_tokens)


def test_find_high_entropy_ignores_identifiers():
    """Verify natural code identifiers are not falsely flagged as high entropy secrets."""
    code_line = "class VeryLongDescriptiveCamelCaseClassNameWithoutAnyDigitsOrSymbols:"
    tokens = find_high_entropy_tokens(code_line, threshold=4.0, min_length=16)
    assert len(tokens) == 0
