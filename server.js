// Hệ thống Web Verify MMO - Phát triển bởi Thái Vũ & Tối ưu hóa cấu trúc bảo mật

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'system.db');

// ADMIN ID
const ADMIN_ID = 6327666718;

// Lấy giờ Việt Nam (UTC+7)
function getVietnamTime() {
    const now = new Date();
    const vietnamTime = new Date(now.getTime() + 7 * 60 * 60 * 1000);
    return vietnamTime;
}

function getVietnamDate() {
    const vietnamTime = getVietnamTime();
    const year = vietnamTime.getUTCFullYear();
    const month = String(vietnamTime.getUTCMonth() + 1).padStart(2, '0');
    const day = String(vietnamTime.getUTCDate()).padStart(2, '0');
    return `${day}-${month}-${year}`;
}

function getVietnamDateTime() {
    const vietnamTime = getVietnamTime();
    const year = vietnamTime.getUTCFullYear();
    const month = String(vietnamTime.getUTCMonth() + 1).padStart(2, '0');
    const day = String(vietnamTime.getUTCDate()).padStart(2, '0');
    const hours = String(vietnamTime.getUTCHours()).padStart(2, '0');
    const minutes = String(vietnamTime.getUTCMinutes()).padStart(2, '0');
    const seconds = String(vietnamTime.getUTCSeconds()).padStart(2, '0');
    return `${day}-${month}-${year} ${hours}:${minutes}:${seconds}`;
}

function getVietnamHour() {
    const vietnamTime = getVietnamTime();
    return vietnamTime.getUTCHours();
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

// HÀM KIỂM TRA GIỚI HẠN TỪ BOT API - QUAN TRỌNG: GỌI ĐẾN BOT (CỔNG 5000)
async function checkDailyLimitFromBot(user_id, task_type) {
    const fetch = require('node-fetch');
    try {
        // Gọi API từ bot đang chạy cùng server (cổng 5000)
        const response = await fetch(`http://localhost:5000/api/bot/check-limit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                secret_key: 'MY_SUPER_SECRET_PASSPHRASE_123',
                user_id: user_id,
                task_type: task_type
            })
        });
        const data = await response.json();
        console.log(`[CHECK LIMIT FROM BOT] User: ${user_id}, Task: ${task_type}, Current: ${data.current_count}, Max: ${data.daily_limit}, Reached: ${data.is_limit_reached}`);
        return {
            allowed: !data.is_limit_reached,
            currentCount: data.current_count,
            dailyLimit: data.daily_limit,
            reward: 300
        };
    } catch (error) {
        console.error('Lỗi gọi API bot check limit:', error);
        // Nếu không gọi được API bot, vẫn cho phép (fallback)
        return { allowed: true, currentCount: 0, dailyLimit: 999, reward: 300 };
    }
}

// Kiểm tra giới hạn nhiệm vụ theo ngày
function checkDailyLimit(user_id, task_type, callback) {
    checkDailyLimitFromBot(user_id, task_type).then(result => {
        callback(null, result.allowed, result.reward, result.dailyLimit, result.currentCount);
    }).catch(err => {
        console.error('Lỗi checkDailyLimit:', err);
        callback(err, true, 300);
    });
}

// Cập nhật giới hạn nhiệm vụ
function updateDailyLimit(user_id, ip, task_type) {
    const today = getVietnamDate();
    
    db.run(`INSERT INTO daily_task_limit (user_id, ip, task_type, task_date) 
            VALUES (?, ?, ?, ?)`, [user_id, ip, task_type, today], (err) => {
        if (err) {
            console.error('Lỗi updateDailyLimit:', err);
        } else {
            console.log(`[UPDATE LIMIT] User: ${user_id}, Task: ${task_type}, IP: ${ip}, Date: ${today}`);
        }
    });
}

// Kiểm tra IP đã dùng cho bao nhiêu user trong ngày (chống clone)
function checkIpUsage(ip, current_user_id, callback) {
    const today = getVietnamDate();
    db.get(`SELECT COUNT(DISTINCT user_id) as user_count FROM daily_task_limit 
            WHERE ip = ? AND task_date = ? AND user_id != ?`,
            [ip, today, current_user_id], (err, row) => {
        if (err) {
            callback(err, 0);
        } else {
            callback(null, row?.user_count || 0);
        }
    });
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
    
    // Xóa token cũ quá 120 phút
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-120 minutes')`);
    
    db.run(`INSERT OR REPLACE INTO active_tokens (token, user_id, task_type, created_at) VALUES (?, ?, ?, datetime('now'))`, 
        [token, String(user_id), task_type], (err) => {
            if (err) {
                return res.status(500).json({ error: "Lỗi ghi token" });
            }
            console.log(`[CREATE TOKEN] Token: ${token.substring(0, 10)}..., User: ${user_id}, Task: ${task_type}`);
            res.json({ status: "success" });
        });
});

// API KIỂM TRA TOKEN - KHÔNG XÓA TOKEN
app.post('/api/check-token', (req, res) => {
    const { secret_key, token, user_id } = req.body;
    
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    
    // KIỂM TRA TOKEN - KHÔNG XÓA
    db.get(`SELECT * FROM active_tokens WHERE token = ? AND user_id = ?`, [token, String(user_id)], (err, row) => {
        if (err || !row) {
            console.log(`[CHECK TOKEN] Token ${token.substring(0, 10)}... KHÔNG HỢP LỆ`);
            return res.json({ valid: false });
        }
        
        console.log(`[CHECK TOKEN] Token ${token.substring(0, 10)}... HỢP LỆ, Task: ${row.task_type}`);
        
        // KHÔNG XÓA TOKEN - giữ nguyên để web verify vẫn hiển thị
        res.json({ 
            valid: true, 
            task_type: row.task_type,
            user_id: row.user_id
        });
    });
});

// Kiểm tra thời gian làm nhiệm vụ
function isWithinTaskTime() {
    const hour = getVietnamHour();
    return hour >= 6 && hour < 24;
}

// Trang xác minh
app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    const currentHour = getVietnamHour();
    const currentDateTime = getVietnamDateTime();
    
    console.log(`[${currentDateTime}] Yêu cầu xác minh token: ${token.substring(0, 10)}... | IP: ${userIP}`);
    
    // Kiểm tra thời gian
    if (!isWithinTaskTime()) {
        return res.send(`
            <!DOCTYPE html>
            <html lang="vi">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>HẾT GIỜ LÀM VIỆC</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                    .container { background: #ffffff; padding: 40px 25px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2); text-align: center; max-width: 450px; width: 100%; }
                    .icon { font-size: 70px; margin-bottom: 20px; }
                    h2 { color: #ff4757; font-size: 26px; margin-bottom: 15px; }
                    p { color: #7f8c8d; font-size: 15px; line-height: 1.6; margin-bottom: 10px; }
                    .time-info { background: #f1f2f6; padding: 15px; border-radius: 12px; margin: 20px 0; }
                    .time-info span { color: #ff4757; font-weight: bold; font-size: 18px; }
                    .footer { font-size: 12px; color: #a4b0be; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">⏰🌙</div>
                    <h2>ĐÃ HẾT THỜI GIAN LÀM NHIỆM VỤ</h2>
                    <div class="time-info">
                        <span>⏱️ ${currentHour}:00</span>
                    </div>
                    <p>Thời gian làm nhiệm vụ: <strong>6:00 - 24:00</strong> hàng ngày (Giờ Việt Nam)</p>
                    <p>📅 Hôm nay: <strong>${currentDateTime.split(' ')[0]}</strong></p>
                    <p>✨ Vui lòng quay lại từ <strong>6:00 sáng</strong> hôm sau!</p>
                    <div class="footer">🛡️ Hệ thống chống gian lận MMO</div>
                </div>
            </body>
            </html>
        `);
    }
    
    // Xóa token cũ quá 120 phút
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-120 minutes')`);
    
    db.get(`SELECT * FROM active_tokens WHERE token = ?`, [token], async (err, row) => {
        if (err || !row) {
            console.log(`[${currentDateTime}] Token không tồn tại: ${token.substring(0, 10)}...`);
            return res.send(`
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOKEN HẾT HẠN</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                        .container { background: #ffffff; padding: 40px 25px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2); text-align: center; max-width: 450px; width: 100%; }
                        .icon { font-size: 70px; margin-bottom: 20px; }
                        h2 { color: #ff4757; font-size: 26px; margin-bottom: 15px; }
                        p { color: #7f8c8d; font-size: 15px; line-height: 1.6; }
                        .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">❌⌛</div>
                        <h2>PHIÊN XÁC MINH KHÔNG TỒN TẠI</h2>
                        <p>Mã liên kết đã hết hiệu lực (tối đa 120 phút)</p>
                        <p>🕐 Thời gian hiện tại: ${currentDateTime}</p>
                        <a href="https://t.me/Vuotlinkcaytienbot" class="btn">🤖 Quay lại Bot</a>
                    </div>
                </body>
                </html>
            `);
        }
        
        const userId = row.user_id;
        const taskType = row.task_type;
        const tokenValue = row.token;
        
        console.log(`[${currentDateTime}] Token hợp lệ cho User: ${userId} | Task: ${taskType}`);
        
        // Kiểm tra giới hạn từ bot
        const limitResult = await checkDailyLimitFromBot(userId, taskType);
        
        if (limitResult.is_limit_reached) {
            console.log(`[${currentDateTime}] TỪ CHỐI: User ${userId} đã đạt giới hạn ${taskType}`);
            db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
            
            return res.send(`
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>GIỚI HẠN NHIỆM VỤ</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                        .container { background: #ffffff; padding: 40px 25px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2); text-align: center; max-width: 450px; width: 100%; }
                        .icon { font-size: 70px; margin-bottom: 20px; }
                        h2 { color: #ff9800; font-size: 24px; margin-bottom: 15px; }
                        .limit-box { background: #fff3e0; padding: 15px; border-radius: 12px; margin: 20px 0; }
                        .limit-count { font-size: 36px; font-weight: bold; color: #ff9800; }
                        .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">📊⏳</div>
                        <h2>BẠN ĐÃ ĐẠT GIỚI HẠN NHIỆM VỤ HÔM NAY</h2>
                        <div class="limit-box">
                            <div>Cổng <strong>${taskType}</strong></div>
                            <div class="limit-count">${limitResult.currentCount}/${limitResult.dailyLimit}</div>
                            <div>lần/ngày</div>
                        </div>
                        <p>📅 Hôm nay: ${currentDateTime.split(' ')[0]}</p>
                        <p>✨ Vui lòng quay lại từ <strong>6:00 sáng</strong> hôm sau!</p>
                        <a href="https://t.me/Vuotlinkcaytienbot" class="btn">🤖 Quay lại Bot</a>
                    </div>
                </body>
                </html>
            `);
        }
        
        // Kiểm tra IP
        checkIpUsage(userIP, userId, (err, ipUserCount) => {
            if (ipUserCount >= 2) {
                console.log(`[${currentDateTime}] CẢNH BÁO TRÙNG IP! User: ${userId}`);
                db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
                notifyAdmin(`🚨 CẢNH BÁO TRÙNG IP!\nUser ID: ${userId}\nIP: ${userIP}\nThời gian: ${currentDateTime}`);
                
                return res.send(`
                    <!DOCTYPE html>
                    <html lang="vi">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>CẢNH BÁO GIAN LẬN</title>
                        <style>
                            * { margin: 0; padding: 0; box-sizing: border-box; }
                            body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #ff4757 0%, #c0392b 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                            .container { background: #ffffff; padding: 40px 25px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2); text-align: center; max-width: 450px; width: 100%; }
                            .icon { font-size: 70px; margin-bottom: 20px; }
                            h2 { color: #c0392b; font-size: 24px; margin-bottom: 15px; }
                            .warning { background: #ffeaa7; padding: 15px; border-radius: 12px; margin: 20px 0; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="icon">🚫⚠️</div>
                            <h2>BẠN KHÔNG THỂ NHẬP KEY VÌ TRÙNG IP</h2>
                            <div class="warning">IP của bạn đã phục vụ ${ipUserCount + 1}/2 tài khoản trong ngày</div>
                            <p>🌐 IP: ${userIP}</p>
                            <p>⏰ Thời gian: ${currentDateTime}</p>
                        </div>
                    </body>
                    </html>
                `);
            }
            
            // Cập nhật limit
            updateDailyLimit(userId, userIP, taskType);
            db.run(`INSERT INTO ip_logs (ip, user_id, user_agent, task_type) VALUES (?, ?, ?, ?)`, 
                    [userIP, userId, userAgent, taskType]);
            
            console.log(`[${currentDateTime}] THÀNH CÔNG! User: ${userId} | Task: ${taskType}`);
            
            // KHÔNG XÓA TOKEN - giữ lại để bot check
            res.send(`
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>🎉 XÁC MINH THÀNH CÔNG!</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 15px; }
                        .container { background: #fff; padding: 30px; border-radius: 20px; text-align: center; max-width: 500px; width: 100%; }
                        h2 { color: #2ed573; font-size: 28px; margin-bottom: 15px; }
                        .key-box { background: #f0f0f0; padding: 15px; border-radius: 10px; margin: 20px 0; word-break: break-all; font-family: monospace; font-size: 14px; }
                        .copy-btn { background: #2ed573; color: white; border: none; padding: 12px 24px; border-radius: 10px; cursor: pointer; font-size: 16px; }
                        .copy-btn:hover { background: #26af5f; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>🎉 VƯỢT LINK THÀNH CÔNG!</h2>
                        <p>Chúc mừng bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p>
                        <div class="reward-box" style="background: linear-gradient(135deg, #667eea, #764ba2); padding: 20px; border-radius: 15px; margin: 20px 0;">
                            <span style="color: #ffd700; font-size: 36px; font-weight: bold;">+${limitResult.reward || 300} ₫</span>
                        </div>
                        <div class="key-title">🔑 MÃ XÁC MINH CỦA BẠN:</div>
                        <div class="key-box" id="keyText">${tokenValue}</div>
                        <button class="copy-btn" onclick="copyKey()">📋 COPY MÃ</button>
                        <p style="margin-top: 20px; font-size: 12px; color: #888;">Sau khi copy, quay lại Bot và dán mã để nhận thưởng!</p>
                    </div>
                    <script>
                        function copyKey() {
                            const text = document.getElementById("keyText").innerText;
                            navigator.clipboard.writeText(text).then(() => alert("✅ Đã sao chép mã! Quay lại Bot để nhận thưởng!"));
                        }
                    </script>
                </body>
                </html>
            `);
        });
    });
});

// API xóa token
app.post('/api/delete-token', (req, res) => {
    const { token } = req.body;
    if (token) {
        db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
        res.json({ status: "deleted" });
    } else {
        res.status(400).json({ error: "Thiếu token" });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', vietnamTime: getVietnamDateTime() });
});

setInterval(() => {
    db.run(`DELETE FROM ip_logs WHERE accessed_at <= datetime('now', '-1 day')`);
    db.run(`DELETE FROM daily_task_limit WHERE task_date < date('now')`);
}, 3600000);

app.listen(PORT, () => console.log(`🚀 Web Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
