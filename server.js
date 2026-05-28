// Hệ thống Web Verify MMO - Phát triển bởi Thái Vũ & Tối ưu hóa cấu trúc bảo mật

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'system.db');

// ADMIN ID
const ADMIN_ID = 6327666718;

function getVietnamDate() {
    const options = { timeZone: 'Asia/Ho_Chi_Minh', day: '2-digit', month: '2-digit', year: 'numeric' };
    const formatter = new Intl.DateTimeFormat('en-GB', options);
    return formatter.format(new Date()).replace(/\//g, '-');
}

function getVietnamDateTime() {
    const options = { timeZone: 'Asia/Ho_Chi_Minh', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    const formatter = new Intl.DateTimeFormat('en-GB', options);
    return formatter.format(new Date()).replace(/\//g, '-').replace(/,/g, ' ');
}

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('❌ Lỗi kết nối DB:', err.message);
    } else {
        console.log('✅ Kết nối SQLite thành công');
        
        db.run(`CREATE TABLE IF NOT EXISTS active_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            task_type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS ip_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_id TEXT,
            user_agent TEXT,
            task_type TEXT,
            accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS daily_task_limit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            ip TEXT,
            task_type TEXT,
            count INTEGER DEFAULT 1,
            task_date TEXT
        )`);
    }
});

app.set('trust proxy', true);
app.use(express.json());

// Gửi thông báo đến Admin qua Telegram
function notifyAdmin(message) {
    const fetch = require('node-fetch');
    const token = '8649791125:AAED_yDtgpml3ioVca-sAgLCBPhVnYS2QcA';
    fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=${ADMIN_ID}&text=${encodeURIComponent(message)}`)
        .catch(err => console.error('Lỗi gửi thông báo admin:', err));
}

// Kiểm tra giới hạn nhiệm vụ theo ngày
function checkDailyLimit(user_id, ip, task_type, callback) {
    const today = getVietnamDate();
    const limits = {
        'LINK4M': { max: 1, reward: 300 },
        'SITE2S': { max: 2, reward: 150 },
        'YEUMONEY': { max: 3, reward: 300 },
        'BBMKTS': { max: 1, reward: 300 },
        'LAYMA': { max: 4, reward: 400 },
        'NHAPMA': { max: 4, reward: 500 },
        'TAPLAYMA': { max: 4, reward: 500 }
    };
    
    const limit = limits[task_type];
    if (!limit) {
        callback(null, true, 300);
        return;
    }
    
    db.get(`SELECT SUM(count) as total FROM daily_task_limit 
            WHERE (user_id = ? OR ip = ?) AND task_type = ? AND task_date = ?`,
            [user_id, ip, task_type, today], (err, row) => {
        if (err) {
            callback(err, true, limit.reward);
            return;
        }
        const currentCount = row?.total || 0;
        if (currentCount >= limit.max) {
            callback(null, false, limit.reward, limit.max, currentCount);
        } else {
            callback(null, true, limit.reward);
        }
    });
}

// Cập nhật giới hạn nhiệm vụ
function updateDailyLimit(user_id, ip, task_type) {
    const today = getVietnamDate();
    db.run(`INSERT INTO daily_task_limit (user_id, ip, task_type, task_date) 
            VALUES (?, ?, ?, ?)`, [user_id, ip, task_type, today]);
}

// API tạo token
app.post('/api/create-token', (req, res) => {
    const { secret_key, user_id, task_type, token } = req.body;
    
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);
    
    db.run(`INSERT OR REPLACE INTO active_tokens (token, user_id, task_type) VALUES (?, ?, ?)`, 
        [token, String(user_id), task_type], (err) => {
            if (err) {
                return res.status(500).json({ error: "Lỗi ghi token" });
            }
            res.json({ status: "success" });
        });
});

// Kiểm tra thời gian làm nhiệm vụ (6H - 24H)
function isWithinTaskTime() {
    const now = new Date();
    const hours = now.getHours();
    return hours >= 6 && hours < 24;
}

// Trang xác minh
app.get('/verify/:token', (req, res) => {
    const token = req.params.token;
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Kiểm tra thời gian
    if (!isWithinTaskTime()) {
        return res.send(`
            <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ff4757; padding: 20px;">
                <h2 style="font-size: 26px;">⏰ ĐÃ HẾT THỜI GIAN LÀM NHIỆM VỤ</h2>
                <p style="font-size: 16px;">Thời gian làm nhiệm vụ từ 6H đến 24H hàng ngày!</p>
                <p style="font-size: 14px;">Vui lòng quay lại từ 6H sáng hôm sau.</p>
            </div>
        `);
    }
    
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);
    
    db.get(`SELECT * FROM active_tokens WHERE token = ?`, [token], (err, row) => {
        if (err || !row) {
            return res.send(`
                <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ff4757; padding: 20px;">
                    <h2>❌ PHIÊN XÁC MINH KHÔNG TỒN TẠI HOẶC ĐÃ HẾT HẠN</h2>
                    <p>Mã liên kết đã hết hiệu lực (tối đa 30 phút)</p>
                </div>
            `);
        }
        
        const userId = row.user_id;
        const taskType = row.task_type;
        
        // Kiểm tra IP trùng
        db.get(`SELECT COUNT(DISTINCT user_id) as count FROM ip_logs 
                WHERE ip = ? AND accessed_at >= datetime('now', '-1 day') AND user_id != ?`,
                [userIP, userId], (err, ipCheck) => {
            
            if (ipCheck && ipCheck.count >= 5) {
                // Thông báo cho Admin
                notifyAdmin(`🚨 CẢNH BÁO TRÙNG IP!\nUser ID: ${userId}\nIP: ${userIP}\nThiết bị: ${userAgent.substring(0, 50)}\nThời gian: ${getVietnamDateTime()}\nLý do: IP đã phục vụ ${ipCheck.count} tài khoản khác trong ngày`);
                
                return res.send(`
                    <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ee5253; padding: 20px;">
                        <h2>⚠️ BẠN KHÔNG THỂ NHẬP KEY VÌ TRÙNG IP</h2>
                        <p>Hệ thống phát hiện địa chỉ mạng của bạn đang chạy quá số lượng tài khoản cho phép (Tối đa 5 nick/IP).</p>
                        <p style="font-size: 12px; color: #666;">Thông tin đã được ghi nhận và báo cáo Admin.</p>
                    </div>
                `);
            }
            
            // Kiểm tra giới hạn nhiệm vụ trong ngày
            checkDailyLimit(userId, userIP, taskType, (err, allowed, reward, maxCount, currentCount) => {
                if (!allowed) {
                    const limits = {
                        'LINK4M': 1, 'SITE2S': 2, 'YEUMONEY': 3, 'BBMKTS': 1, 'LAYMA': 4, 'NHAPMA': 4, 'TAPLAYMA': 4
                    };
                    return res.send(`
                        <div style="font-family:'Segoe UI', Arial, sans-serif; text-align:center; margin-top:100px; color:#ff4757; padding: 20px;">
                            <h2>⚠️ BẠN ĐÃ ĐẠT GIỚI HẠN NHIỆM VỤ HÔM NAY</h2>
                            <p>Cổng <strong>${taskType}</strong> chỉ được vượt <strong>${limits[taskType]}</strong> lần/ngày!</p>
                            <p>Bạn đã vượt: ${currentCount}/${limits[taskType]}</p>
                            <p>Vui lòng quay lại từ 6H sáng hôm sau.</p>
                        </div>
                    `);
                }
                
                // Ghi log và cập nhật giới hạn
                db.run(`INSERT INTO ip_logs (ip, user_id, user_agent, task_type) VALUES (?, ?, ?, ?)`, 
                        [userIP, userId, userAgent, taskType]);
                updateDailyLimit(userId, userIP, taskType);
                
                // Xóa token sau khi sử dụng thành công
                db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
                
                // Hiển thị trang thành công với mã key
                res.send(`
                    <!DOCTYPE html>
                    <html lang="vi">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XÁC MINH THÀNH CÔNG</title>
                        <style>
                            * { margin: 0; padding: 0; box-sizing: border-box; }
                            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                            .container { background: #ffffff; padding: 35px 25px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2); text-align: center; max-width: 500px; width: 100%; }
                            .icon-success { font-size: 70px; margin-bottom: 15px; animation: bounce 0.5s ease; }
                            @keyframes bounce { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
                            h2 { color: #2ed573; font-size: 26px; margin-bottom: 10px; font-weight: 700; }
                            p { color: #7f8c8d; font-size: 14px; line-height: 1.6; margin-bottom: 20px; }
                            .reward-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 12px; margin-bottom: 20px; }
                            .reward-box span { color: #ffd700; font-size: 28px; font-weight: bold; display: block; }
                            .key-title { font-size: 13px; font-weight: bold; color: #57606f; text-transform: uppercase; text-align: left; margin-bottom: 6px; }
                            .key-container { position: relative; display: flex; align-items: center; background: #f1f2f6; border: 2px solid #2ed573; padding: 12px 15px; border-radius: 12px; margin-bottom: 25px; }
                            .key-text { font-family: 'Courier New', monospace; font-size: 14px; font-weight: bold; color: #ff4757; flex: 1; text-align: left; overflow-x: auto; word-break: break-all; }
                            .copy-btn { background: #2ed573; color: white; border: none; padding: 8px 16px; font-size: 12px; font-weight: bold; border-radius: 8px; cursor: pointer; transition: 0.2s; margin-left: 10px; }
                            .copy-btn:hover { background: #26af5f; transform: scale(1.05); }
                            .footer-info { font-size: 11px; color: #a4b0be; border-top: 1px solid #f1f2f6; padding-top: 15px; text-align: left; line-height: 1.6; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="icon-success">🎉✨</div>
                            <h2>VƯỢT LINK THÀNH CÔNG!</h2>
                            <div class="reward-box">
                                <span>+${reward}₫</span>
                                <small style="color: white;">Đã cộng vào tài khoản của bạn</small>
                            </div>
                            <p>Bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p>
                            
                            <div class="key-title">🔑 MÃ XÁC MINH CỦA BẠN:</div>
                            <div class="key-container">
                                <div class="key-text" id="keyText">${token}</div>
                                <button class="copy-btn" onclick="copyKey()">📋 COPY</button>
                            </div>
                            
                            <div class="footer-info">
                                🌐 IP: ${userIP}<br>
                                📱 Thiết bị: ${userAgent.substring(0, 40)}...<br>
                                ⏰ Thời gian: ${getVietnamDateTime()}<br>
                                🛡️ <em>Dán mã này vào Bot Telegram để nhận thưởng!</em>
                            </div>
                        </div>
                        <script>
                            function copyKey() {
                                navigator.clipboard.writeText(document.getElementById("keyText").innerText).then(() => {
                                    alert("✅ Đã sao chép mã! Quay lại Bot Telegram dán mã để nhận tiền.");
                                }).catch(() => {
                                    alert("✅ Đã sao chép mã thành công!");
                                });
                            }
                        </script>
                    </body>
                    </html>
                `);
            });
        });
    });
});

// Xóa IP logs cũ sau 24H
setInterval(() => {
    db.run(`DELETE FROM ip_logs WHERE accessed_at <= datetime('now', '-1 day')`);
    db.run(`DELETE FROM daily_task_limit WHERE task_date < date('now')`);
    console.log('🗑️ Đã xóa logs cũ sau 24H');
}, 3600000);

app.listen(PORT, () => console.log(`🚀 Web Verify Server chạy tại cổng ${PORT}`));
