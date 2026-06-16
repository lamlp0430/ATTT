# 🗳️ Hệ thống Bầu cử Điện tử (E-Voting) Tích hợp RSA & Blockchain

Dự án Hệ thống Bầu cử Điện tử (E-Voting) được phát triển nhằm giải quyết bài toán bảo mật, tính ẩn danh và tính toàn vẹn của dữ liệu trong quá trình bỏ phiếu. Hệ thống áp dụng **Chữ ký số RSA**, băm **SHA-256** và cấu trúc **Blockchain-lite** để đảm bảo không một ai (kể cả quản trị viên hay hacker) có thể can thiệp hay thay đổi kết quả bầu cử.

## 🌟 Các tính năng nổi bật
- **🔐 Bảo mật Đa tầng:** Mã hóa mật khẩu bằng Bcrypt, quản lý phiên bằng JWT (JSON Web Token) kết hợp cơ chế Blacklist chống chiếm quyền.
- **🔗 Cấu trúc Blockchain:** Mỗi lá phiếu được liên kết với nhau bằng mã băm (Previous Hash -> Vote Hash).
- **✍️ Chữ ký số RSA:** Định danh tính hợp lệ của lá phiếu mà vẫn đảm bảo tính ẩn danh 100% của cử tri.
- **⏳ Quản lý Thời gian thực:** Admin có thể hẹn giờ mở/đóng hòm phiếu, hiển thị đồng hồ đếm ngược trực tiếp cho cử tri.
- **🔍 Kiểm toán Độc lập:** Cổng kiểm toán dành riêng cho Auditor để quét toàn bộ chuỗi khối và phát hiện gian lận.
- **🐳 Triển khai Dễ dàng:** Đóng gói hoàn chỉnh bằng Docker & Docker Compose.

## 🛠️ Công nghệ sử dụng
- **Backend:** FastAPI (Python), Uvicorn, PyJWT, Cryptography.
- **Database:** PostgreSQL 15.
- **Frontend:** HTML5, JavaScript (Vanilla), TailwindCSS.
- **DevOps:** Docker, Docker Compose.

---

## 🚀 Hướng dẫn cài đặt và chạy dự án (Quick Start)

Dự án đã được đóng gói sẵn bằng Docker, vì vậy bạn **không cần** cài đặt Python hay PostgreSQL lên máy tính của mình. Chỉ cần làm theo các bước sau:

### Yêu cầu hệ thống:
* Đã cài đặt [Git](https://git-scm.com/)
* Đã cài đặt [Docker Desktop](https://www.docker.com/products/docker-desktop) (Đảm bảo Docker đang chạy ngầm).

### Các bước khởi chạy:

**Bước 1:** Clone (tải) mã nguồn từ GitHub về máy:
```bash
git clone [https://github.com/lamlp0430/evoting-n11.git](https://github.com/lamlp0430/evoting-n11.git)
cd evoting-n11
******
Khởi chạy hệ thống bang Docker Compose

docker-compose up --build -d

******
Mở trình duyệt truy cập hệ thống http://localhost:8000
******
👥 Tài khoản Thử nghiệm (Test Accounts)

admin01    123456
auditor01  123456
voter01    123456
voter01    123456
******
Hướng dẫn sử dụng cơ bản (Demo Workflow)
Đăng nhập bằng admin01. Kéo xuống phần Cài đặt Lịch Bầu Cử, thiết lập thời gian mở và đóng hòm phiếu. Có thể thêm ứng viên mới ở phía dưới. Đăng xuất.

Đăng nhập bằng voter01. Màn hình sẽ hiển thị đồng hồ đếm ngược. Tiến hành chọn ứng cử viên và bấm "Bỏ phiếu & Ký RSA".

Lưu lại đoạn Mã tra cứu (Receipt Hash) hiện lên trên màn hình. Đăng xuất.

Ở màn hình trang chủ (chưa đăng nhập), dán mã tra cứu vào ô Tra cứu biên nhận để kiểm tra lá phiếu của mình đã nằm trên chuỗi khối hay chưa.

Đăng nhập bằng auditor01. Nhấn "Xác minh Toàn vẹn & Chữ ký RSA" để hệ thống quét toàn bộ hòm phiếu. Kết quả sẽ báo màu xanh (SAFE) nếu không có hacker nào xâm nhập.
******
⚠️ Khắc phục sự cố (Troubleshooting)
Lỗi port is already allocated: Xảy ra khi cổng 8000 hoặc 5432 trên máy bạn đang bị ứng dụng khác chiếm dụng. Hãy tắt các ứng dụng đó (như XAMPP, Postgres local) hoặc sửa lại port trong file docker-compose.yml.

Muốn reset lại toàn bộ Database: Gõ lệnh sau để xóa bộ nhớ của Docker và chạy lại:

Bash
docker-compose down -v
docker-compose up --build -d
******
