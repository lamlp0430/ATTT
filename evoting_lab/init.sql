-- Khởi tạo trạng thái bầu cử (FR-08)
CREATE TABLE election_status (
    id INT PRIMARY KEY,
    is_active BOOLEAN DEFAULT TRUE
);
INSERT INTO election_status (id, is_active) VALUES (1, TRUE);

-- Khởi tạo trạng thái bầu cử (FR-08) CÓ THỜI GIAN THỰC
DROP TABLE IF EXISTS election_status CASCADE;
CREATE TABLE election_status (
    id INT PRIMARY KEY,
    is_active BOOLEAN DEFAULT TRUE,
    start_time TIMESTAMP,
    end_time TIMESTAMP
);
-- Mặc định khởi tạo thời gian mở từ năm 2000 đến 2050 để hệ thống chạy tạm trước khi Admin set lại
INSERT INTO election_status (id, is_active, start_time, end_time)
VALUES (1, TRUE, '2000-01-01 00:00:00', '2050-12-31 23:59:59');

-- Quản lý Token bị thu hồi (FR-05)
CREATE TABLE revoked_tokens (
    token TEXT PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Khởi tạo danh sách ứng viên (Cập nhật thêm Profile chi tiết)
DROP TABLE IF EXISTS candidates CASCADE;
CREATE TABLE candidates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    party VARCHAR(100) DEFAULT 'Độc lập',
    image_url TEXT,       -- Link ảnh chân dung
    dob DATE,             -- Ngày tháng năm sinh
    position VARCHAR(255),-- Chức vụ hiện tại
    education VARCHAR(255),-- Trình độ học vấn
    details TEXT          -- Thông tin/Tiểu sử chi tiết
);

-- Thêm thử 1 ứng viên mẫu để có sẵn dữ liệu test (Admin có thể thêm sau)
INSERT INTO candidates (name, party, image_url, dob, position, education, details)
VALUES ('Alice', 'Đảng Công nghệ', 'https://cdn-icons-png.flaticon.com/512/4140/4140048.png', '1985-10-15', 'Giám đốc Công nghệ (CTO)', 'Tiến sĩ Trí tuệ Nhân tạo', 'Ứng cử viên xuất sắc với hơn 10 năm kinh nghiệm trong lĩnh vực bảo mật và Blockchain.');

-- Thêm cột rsa_public_key và rsa_private_key (Phục vụ ký số RSA)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    has_voted BOOLEAN DEFAULT FALSE,
    rsa_public_key TEXT,
    rsa_private_key TEXT
    -- Ghi chú: Lưu private_key ở server chỉ phục vụ Lab mô phỏng.
    -- Thực tế cử tri tự giữ Private Key.
);

INSERT INTO users (username, password_hash, role) VALUES
('voter01', '$2b$12$dRtisFjjUtSonJ2C/QHoYe6ucnSMJuuQHitEp.RodUwRS7sVwBkWa', 'voter'),
('voter02', '$2b$12$dRtisFjjUtSonJ2C/QHoYe6ucnSMJuuQHitEp.RodUwRS7sVwBkWa', 'voter'),
('auditor01', '$2b$12$dRtisFjjUtSonJ2C/QHoYe6ucnSMJuuQHitEp.RodUwRS7sVwBkWa', 'auditor'),
('admin01', '$2b$12$dRtisFjjUtSonJ2C/QHoYe6ucnSMJuuQHitEp.RodUwRS7sVwBkWa', 'admin');

-- Hòm phiếu điện tử (Bổ sung Chữ ký số RSA)
CREATE TABLE votes (
    id SERIAL PRIMARY KEY,
    voter_hash VARCHAR(64) NOT NULL,
    candidate_id INT REFERENCES candidates(id),
    vote_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    rsa_signature TEXT NOT NULL -- FR-03: Chữ ký số của cử tri
);