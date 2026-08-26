"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = f"lab24-agent-{uuid4().hex[:12]}"

    def invoke(tool_name: str, args: dict, classification: str, purpose: str,
               run_id: str, depth: int, egress: bool, function):
        context = policy.PolicyContext(classification, purpose, agent_id, depth, egress)
        allowed, reason = policy.check(context)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_id": agent_id,
            "agent_owner": agent_id,
            "run_id": run_id,
            "tool": tool_name,
            "args_hash": hashlib.sha256(
                json.dumps(args, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }
        ledger.append(entry, ledger_path)
        return function() if allowed else None

    # Run A owns only the untrusted-content capability.
    docs = invoke(
        "search_docs", {"query": message}, "internal", "summarize-tickets",
        "run-a", 0, False, lambda: tools.search_docs(message),
    ) or []
    combined = "\n\n".join(doc["text"] for doc in docs)
    injection = llm.find_injection(combined)

    # The only Run A -> Run B hand-off is a typed list derived from filenames.
    ticket_ids = sorted({
        int(match.group(1))
        for doc in docs
        if (match := re.fullmatch(r"ticket-(\d+)(?:b)?\.md", str(doc.get("id", ""))))
    })
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    customer_ids = sorted({
        str(customer["customer_id"])
        for customer in customers
        if set(ticket_ids).intersection(customer.get("related_tickets", []))
    })

    # Run B never receives document text and has no egress capability.
    for customer_id in customer_ids:
        invoke(
            "read_customer", {"customer_id": customer_id}, "restricted",
            "support-ticket-lookup", "run-b", 1, False,
            lambda customer_id=customer_id: tools.read_customer(customer_id),
        )

    # Record the attempted exfiltration, but policy denies it before execution.
    if injection is not None:
        invoke(
            "http_post", {"url": injection.target_url}, "restricted",
            "document-requested-egress", "run-egress", 1, True,
            lambda: tools.http_post(injection.target_url, {}),
        )

    return llm.summarize(docs)
