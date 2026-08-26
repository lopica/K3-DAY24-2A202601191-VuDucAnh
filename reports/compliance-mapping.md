# Compliance mapping

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade; xem stretch goal #3 trong Guide. | `Guide.md:173` |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory ghi rõ đường sang model provider và yêu cầu lưu hồ sơ. | `reports/dpia-lite.md:25` |
| ASI03 — privilege abuse | Per-run agent identity, delegation depth và egress policy; identity được lưu trong ledger. | `agent/runner.py:71`, `agent/policy.py:39`, `reports/ledger.jsonl:1` |
| ASI01 — goal hijack | Trifecta split: Run B chỉ nhận ticket ID typed từ tên file; attempted egress bị deny. | `agent/runner.py:102`, `reports/attack-after.log:2`, `reports/ledger.jsonl:22` |
| ISO 42001 Clause 5-6 | Policy-as-code có test reviewable và evidence quyết định. | `agent/policy.py:39`, `tests/test_policy.py:8`, `reports/ledger.jsonl:22` |
