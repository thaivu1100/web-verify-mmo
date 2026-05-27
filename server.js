// Hệ thống Web Verify MMO - Phát triển bởi Thái Vũ & Tối ưu hóa cấu trúc bảo mật
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
// Render sử dụng biến PORT môi trường tự động cấp phát, mặc định là 3000 nếu chạy local
const PORT = process.env.PORT || 3000;

// Cấu hình thư mục lưu trữ DB. Trên Render, file DB nằm cùng thư mục code sẽ đọc ghi mượt mà
const DB_PATH = path.join(__dirname, 'system.db');

// 🎯 Hàm lấy ngày chuẩn múi giờ Việt Nam (dd-mm-yyyy) để đồng bộ tuyệt đối khi cần đối soát dữ liệu với Bot
function getVietnamDate() {
    const options = { timeZone: 'Asia/Ho_Chi_Minh', day: '2-digit', month: '2-digit', year: 'numeric' };
    const formatter = new Intl.DateTimeFormat('en-GB', options);
    return formatter.format(new Date()).replace(/\//g, '-'); 
}

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('❌ Lỗi kết nối Cơ sở dữ liệu Web:', err.message);
    } else {
        console.log('✅ Đã kết nối SQLite thành công tại:', DB_PATH);
        // Tạo bảng chứa Token tạm thời do Bot đẩy sang
        db.run(`CREATE TABLE IF NOT EXISTS active_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            task_type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        // Tạo bảng Log ghi vết IP, Thiết bị để kiểm tra spam chống cheat
        db.run(`CREATE TABLE IF NOT EXISTS ip_logs (
            ip TEXT,
            user_id TEXT,
            user_agent TEXT,
            accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// BẮT BUỘC: Cho phép Express đọc IP thật từ proxy trung gian của Render/Cloudflare
app.set('trust proxy', true);
app.use(express.json());

// ─────────────────────────────────────────────────────────────────
// API 1: NHẬN TOKEN TỪ BOT TELEGRAM ĐẨY SANG
// ─────────────────────────────────────────────────────────────────
app.post('/api/create-token', (req, res) => {
    const { secret_key, user_id, task_type, token } = req.body;
    
    // Khóa bảo mật đối soát, chỉ cho phép Bot của bạn gọi vào endpoint này
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Yêu cầu bị từ chối! Sai Secret Key." });
    }

    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin dữ liệu tạo phiên." });
    }

    // [TỐI ƯU BẢO MẬT]: Tự động dọn dẹp tất cả token cũ đã quá hạn 30 phút trước khi nạp token mới để nhẹ DB
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);

    // Đồng bộ ép kiểu dữ liệu user_id về dạng Chuỗi (String) để tránh lỗi lệch kiểu dữ liệu
    db.run(`INSERT OR REPLACE INTO active_tokens (token, user_id, task_type) VALUES (?, ?, ?)`, 
        [token, String(user_id), task_type], (err) => {
            if (err) {
                return res.status(500).json({ error: "Lỗi ghi dữ liệu token vào DB: " + err.message });
            }
            res.json({ status: "success" });
        }
    );
});

// ─────────────────────────────────────────────────────────────────
// TRANG ĐÍCH: NƠI USER NHẢY VỀ SAU KHI VƯỢT XONG SHORTLINK
// ─────────────────────────────────────────────────────────────────
app.get('/verify/:token', (req, res) => {
    const token = req.params.token;
    
    // Lấy chính xác IP thật của người dùng (Render Proxy đã được trust ở trên)
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // Tự động quét dọn dẹp các token rác hết hạn
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);

    // Bước 1: Check xem token có hợp lệ trong cơ sở dữ liệu không
    db.get(`SELECT * FROM active_tokens WHERE token = ?`, [token], (err, row) => {
        if (err || !row) {
            return res.send(`
                <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ff4757; padding: 20px;">
                    <h2 style="font-size: 26px;">❌ LỖI: PHIÊN XÁC MINH KHÔNG TỒN TẠI HOẶC ĐÃ HẾT HẠN</h2>
                    <p style="font-size: 16px; color: #57606f; margin-top: 10px;">Mã liên kết đã hết hiệu lực (tối đa 30 phút) hoặc bạn đã hoàn thành nhiệm vụ này trước đó rồi!</p>
                    <p style="font-size: 14px; color: #747d8c;">Vui lòng quay lại Telegram Bot để lấy liên kết mới.</p>
                </div>
            `);
        }

        const userId = row.user_id;
        const taskType = row.task_type;

        // Bước 2: Thuật toán Anti-Fraud: Quét xem IP này trong vòng 24h qua đã giải hộ cho bao nhiêu tài khoản khác nhau rồi
        db.get(`SELECT COUNT(DISTINCT user_id) as count FROM ip_logs WHERE ip = ? AND accessed_at >= datetime('now', '-1 day') AND user_id != ?`, 
        [userIP, userId], (err, ipCheck) => {
            
            // Nếu 1 IP mà cố tình đi giải link cho hơn 5 tài khoản khác nhau trong ngày => Khóa ngay lập tức
            if (ipCheck && ipCheck.count >= 5) {
                return res.send(`
                    <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ee5253; padding: 20px;">
                        <h2 style="font-size: 26px;">⚠️ CẢNH BÁO: PHIÊN XÁC THỰC BỊ KHÓA DO GIAN LẬN</h2>
                        <p style="font-size: 16px; margin-top: 10px;">Hệ thống phát hiện địa chỉ mạng của bạn đang chạy quá số lượng tài khoản cho phép (Tối đa 5 nick/IP).</p>
                        <p style="font-size: 14px; color: #57606f;">Nghiêm cấm dùng tool cày clone, mạng ảo VPN hoặc Proxy để cheat link thưởng!</p>
                    </div>
                `);
            }

            // Bước 3: Ghi dữ liệu log IP hợp lệ vào bộ nhớ hệ thống
            db.run(`INSERT INTO ip_logs (ip, user_id, user_agent) VALUES (?, ?, ?)`, [userIP, userId, userAgent]);

            // Bước 4: Trả giao diện lấy Key đẹp mắt cho User sao chép
            res.send(`
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>XÁC MINH HOÀN THÀNH - CHỐNG CHEAT</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                        .container { background: #ffffff; padding: 35px 25px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08); text-align: center; max-width: 450px; width: 100%; border-top: 6px solid #2ed573; }
                        .icon-success { font-size: 60px; color: #2ed573; margin-bottom: 15px; }
                        h2 { color: #2c3e50; font-size: 22px; margin-bottom: 10px; font-weight: 700; }
                        p { color: #7f8c8d; font-size: 14px; line-height: 1.5; margin-bottom: 20px; }
                        .key-title { font-size: 13px; font-weight: bold; color: #57606f; text-transform: uppercase; text-align: left; margin-bottom: 6px; }
                        .key-container { position: relative; display: flex; align-items: center; background: #f1f2f6; border: 2px dashed #2ed573; padding: 12px 15px; border-radius: 8px; margin-bottom: 25px; }
                        .key-text { font-family: 'Courier New', Courier, monospace; font-size: 16px; font-weight: bold; color: #ff4757; width: 75%; text-align: left; overflow-x: auto; white-space: nowrap; word-break: break-all; }
                        .copy-btn { background: #2ed573; color: white; border: none; padding: 8px 12px; font-size: 12px; font-weight: bold; border-radius: 6px; cursor: pointer; transition: 0.2s; position: absolute; right: 10px; }
                        .copy-btn:hover { background: #26af5f; }
                        .footer-info { font-size: 11px; color: #a4b0be; border-top: 1px solid #f1f2f6; padding-top: 15px; text-align: left; line-height: 1.6; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon-success">🎉</div>
                        <h2>VƯỢT LINK THÀNH CÔNG!</h2>
                        <p>Bạn đã hoàn thành nhiệm vụ cổng <strong>${taskType}</strong>. Sao chép Mã xác minh (Key) dưới đây để nhận tiền thưởng.</p>
                        
                        <div class="key-title">Mã xác minh của bạn:</div>
                        <div class="key-container">
                            <div class="key-text" id="keyText">${token}</div>
                            <button class="copy-btn" onclick="copyKey()">COPY</button>
                        </div>

                        <div class="footer-info">
                            🌐 IP mạng: ${userIP}<br>
                            📱 Thiết bị: ${userAgent.substring(0, 45)}...<br>
                            🛡️ <em>Hệ thống bảo mật ghi nhận tự động chống Spam.</em>
                        </div>
                    </div>

                    <script>
                        function copyKey() {
                            var copyText = document.getElementById("keyText").innerText;
                            navigator.clipboard.writeText(copyText).then(function() {
                                alert("👉 Đã sao chép mã thành công! Hãy quay lại Bot Telegram dán mã để lấy tiền.");
                            }).catch(function() {
                                var input = document.createElement("input");
                                input.value = copyText;
                                document.body.appendChild(input);
                                input.select();
                                document.execCommand("copy");
                                document.body.removeChild(input);
                                alert("👉 Đã sao chép mã thành công!");
                            });
                        }
                    </script>
                </body>
                </html>
            `);
            
            // 💡 QUAN TRỌNG: KHÔNG thực hiện DELETE token ở đây nữa! 
            // Token sẽ được lưu giữ an toàn để người dùng có thể F5 tải lại trang thoải mái hoặc không bị các tool quét link nuốt mất mã.
            // Các token cũ sẽ tự động bị xóa triệt để sau 30 phút ở cổng nhận /api/create-token.
        });
    });
});

// Khởi chạy server
app.listen(PORT, () => console.log(`🚀 Web Verify MMO Server đang chạy cực tốt tại cổng ${PORT}`));
