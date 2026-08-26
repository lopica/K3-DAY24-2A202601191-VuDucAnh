# DPIA-lite (1 trang)

## 1. Dữ liệu gì

`search_docs` đọc nội dung ticket hỗ trợ tổng hợp trong `corpus/`. Ticket
có thể chứa customer ID và free text không tin cậy. `read_customer` đọc
kho dữ liệu restricted gồm tên, CCCD, số điện thoại, số tài khoản ngân
hàng, email và danh sách ticket liên quan. `http_post` là kênh egress,
nhưng chỉ được phép kỹ thuật tới sink lab trên `localhost:9999`.

PII detector nhận diện CCCD, điện thoại, tài khoản ngân hàng và email;
`redact` cung cấp cơ chế thay thế trước khi nội dung cần được chia sẻ.

## 2. Mục đích gì

Mục đích là tổng hợp ticket hỗ trợ và tra cứu đúng hồ sơ có quan hệ với
ticket để xử lý yêu cầu. Không dùng PII cho quảng cáo, profiling hoặc mục
đích thứ cấp. Run B chỉ tra cứu customer ID suy ra từ nguồn tin cậy
`related_tickets`, không tin customer ID xuất hiện trong free text.

Nguyên tắc tối thiểu hoá: Run A không đọc private store; Run B không nhận
document text và không có egress. Ledger chỉ giữ hash của tham số, không
ghi nội dung PII của đối số tool.

## 3. Chảy đi đâu

Luồng nội bộ: corpus → Run A → phần tóm tắt; tên file → danh sách ticket ID
typed → ánh xạ `related_tickets` → Run B → private store. Quyết định tool
đi vào `reports/ledger.jsonl` dưới dạng metadata và hash-chain.

Ở đường chấm mặc định `--mock`, không có API model bên ngoài và sink sau
containment rỗng. Sink chỉ là localhost, dùng dữ liệu synthetic. Nếu chạy
`--model claude-...`, document text được gửi tới API của model provider;
đây có thể là chuyển dữ liệu xuyên biên giới và phải được ghi vào hồ sơ,
đánh giá nơi xử lý/lưu trữ, căn cứ xử lý, thời hạn lưu và cơ chế đáp ứng
yêu cầu trong 60 ngày theo NĐ 356/2025 trước khi bật.

Control: policy deny mọi tổ hợp `restricted + egress_enabled`; hard
allowlist của lab giới hạn network ở localhost; trifecta split ngăn một
run đồng thời có untrusted content, private data và egress. Hash-chain
ledger cung cấp bằng chứng mọi allow/deny có reason và phát hiện sửa đổi.
