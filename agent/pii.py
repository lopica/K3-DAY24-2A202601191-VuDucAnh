"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL = re.compile(r"(?<![\w@])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w@])")
_DIGITS = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
_PHONE = re.compile(r"(?<!\d)0(?:[ -]?\d){9,10}(?!\d)")


def _near_label(text: str, start: int, labels: tuple[str, ...]) -> bool:
    prefix = text[max(0, start - 64) : start].casefold()
    return any(label in prefix for label in labels)


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    for match in _EMAIL.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})

    occupied: list[tuple[int, int]] = []
    for match in _PHONE.finditer(text):
        if _near_label(text, match.start(), ("sđt", "điện thoại", "phone")):
            entities.append({"type": "VN_PHONE", "start": match.start(), "end": match.end()})
            occupied.append(match.span())

    for match in _DIGITS.finditer(text):
        if any(match.start() < end and start < match.end() for start, end in occupied):
            continue
        if _near_label(text, match.start(), ("cccd", "căn cước")) and len(match.group()) == 12:
            entity_type = "VN_CCCD"
        elif _near_label(text, match.start(), ("stk", "tài khoản", "bank account")):
            entity_type = "VN_BANK_ACCOUNT"
        else:
            continue
        entities.append({"type": entity_type, "start": match.start(), "end": match.end()})

    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    result = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        result = result[: entity["start"]] + f"[REDACTED_{entity['type']}]" + result[entity["end"] :]
    return result
