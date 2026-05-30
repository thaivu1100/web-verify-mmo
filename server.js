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

// Kiểm tra giới hạn nhiệm vụ theo ngày
function checkDailyLimit(user_id, task_type, callback) {
    const today = getVietnamDate();
    const limits = {
        'LINK4M': { max: 1, reward: 300 },
        'SITE2S': { max: 2, reward: 300 },
        'YEUMONEY': { max: 3, reward: 300 },
        'BBMKTS': { max: 1, reward: 300 },
        'LAYMA': { max: 4, reward: 400 },
        'NHAPMA': { max: 4, reward: 500 },
        'TAPLAYMA': { max: 4, reward: 500 },
        'LINK2M': { max: 2, reward: 300 },
        'SHRINKME': { max: 1, reward: 50 }
    };
    
    const limit = limits[task_type];
    if (!limit) {
        callback(null, true, 300, 0, 0);
        return;
    }
    
    db.get(`SELECT COUNT(*) as total FROM daily_task_limit 
            WHERE user_id = ? AND task_type = ? AND task_date = ?`,
            [user_id, task_type, today], (err, row) => {
        if (err) {
            console.error('Lỗi checkDailyLimit:', err);
            callback(err, true, limit.reward);
            return;
        }
        const currentCount = row?.total || 0;
        console.log(`[CHECK LIMIT] User: ${user_id}, Task: ${task_type}, Current: ${currentCount}, Max: ${limit.max}`);
        
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
    
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);
    
    db.run(`INSERT OR REPLACE INTO active_tokens (token, user_id, task_type) VALUES (?, ?, ?)`, 
        [token, String(user_id), task_type], (err) => {
            if (err) {
                return res.status(500).json({ error: "Lỗi ghi token" });
            }
            res.json({ status: "success" });
        });
});

// API KIỂM TRA TOKEN
app.post('/api/check-token', (req, res) => {
    const { secret_key, token, user_id } = req.body;
    
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    
    db.get(`SELECT * FROM active_tokens WHERE token = ? AND user_id = ?`, [token, String(user_id)], (err, row) => {
        if (err || !row) {
            return res.json({ valid: false });
        }
        
        db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
        
        res.json({ 
            valid: true, 
            task_type: row.task_type,
            user_id: row.user_id
        });
    });
});

// Kiểm tra thời gian làm nhiệm vụ (6H - 24H theo giờ Việt Nam)
function isWithinTaskTime() {
    const hour = getVietnamHour();
    return hour >= 6 && hour < 24;
}

// Trang xác minh - 🔧 SỬA LỖI: Kiểm tra giới hạn NGAY TỪ ĐẦU
app.get('/verify/:token', (req, res) => {
    const token = req.params.token;
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    const currentHour = getVietnamHour();
    const currentDateTime = getVietnamDateTime();
    
    console.log(`[${currentDateTime}] Yêu cầu xác minh token: ${token.substring(0, 10)}... | IP: ${userIP} | Giờ VN: ${currentHour}`);
    
    // Kiểm tra thời gian
    if (!isWithinTaskTime()) {
        console.log(`[${currentDateTime}] Từ chối: Ngoài giờ làm việc (${currentHour}h)`);
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
    
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-30 minutes')`);
    
    db.get(`SELECT * FROM active_tokens WHERE token = ?`, [token], (err, row) => {
        if (err || !row) {
            console.log(`[${currentDateTime}] Token không hợp lệ hoặc đã hết hạn: ${token.substring(0, 10)}...`);
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
                        <p>Mã liên kết đã hết hiệu lực (tối đa 30 phút)</p>
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
        
        console.log(`[${currentDateTime}] Xử lý token cho User: ${userId} | Task: ${taskType} | IP: ${userIP}`);
        
        // 🔧 SỬA LỖI: KIỂM TRA GIỚI HẠN NGAY TỪ ĐẦU TRƯỚC KHI XỬ LÝ
        checkDailyLimit(userId, taskType, (err, allowed, reward, maxCount, currentCount) => {
            const limits = {
                'LINK4M': 1, 'SITE2S': 2, 'YEUMONEY': 3, 'BBMKTS': 1, 'LAYMA': 4, 'NHAPMA': 4, 'TAPLAYMA': 4, 'LINK2M': 2, 'SHRINKME': 1
            };
            
            // Nếu đã đạt giới hạn, KHÔNG cho vào web - trả về trang lỗi ngay
            if (!allowed) {
                console.log(`[${currentDateTime}] TỪ CHỐI NGAY TỪ ĐẦU: User ${userId} đã đạt giới hạn ${taskType} (${currentCount}/${limits[taskType]})`);
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
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="icon">📊⏳</div>
                            <h2>BẠN ĐÃ ĐẠT GIỚI HẠN NHIỆM VỤ HÔM NAY</h2>
                            <div class="limit-box">
                                <div>Cổng <strong>${taskType}</strong></div>
                                <div class="limit-count">${currentCount}/${limits[taskType]}</div>
                                <div>lần/ngày</div>
                            </div>
                            <p>📅 Hôm nay: ${currentDateTime.split(' ')[0]}</p>
                            <p>✨ Vui lòng quay lại từ <strong>6:00 sáng</strong> hôm sau!</p>
                            <a href="https://t.me/Vuotlinkcaytienbot" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 10px;">🤖 Quay lại Bot</a>
                        </div>
                    </body>
                    </html>
                `);
            }
            
            // Bước 1: Kiểm tra IP đã dùng cho bao nhiêu user (chống clone - giới hạn 2 user/IP)
            checkIpUsage(userIP, userId, (err, ipUserCount) => {
                if (err) {
                    console.error('Lỗi checkIpUsage:', err);
                }
                
                if (ipUserCount >= 2) {
                    console.log(`[${currentDateTime}] 🚨 CẢNH BÁO TRÙNG IP! User: ${userId} | IP: ${userIP} | Số tài khoản: ${ipUserCount + 1}`);
                    notifyAdmin(`🚨 CẢNH BÁO TRÙNG IP (${ipUserCount + 1}/2 TK)!\nUser ID: ${userId}\nIP: ${userIP}\nThiết bị: ${userAgent.substring(0, 50)}\nThời gian: ${currentDateTime}\nLý do: IP đã phục vụ ${ipUserCount} tài khoản khác trong ngày`);
                    
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
                                p { color: #7f8c8d; font-size: 14px; line-height: 1.6; margin-bottom: 10px; }
                                .warning { background: #ffeaa7; padding: 15px; border-radius: 12px; margin: 20px 0; color: #d63031; }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="icon">🚫⚠️</div>
                                <h2>BẠN KHÔNG THỂ NHẬP KEY VÌ TRÙNG IP</h2>
                                <div class="warning">
                                    <strong>⚠️ CẢNH BÁO HỆ THỐNG ⚠️</strong><br>
                                    IP của bạn đã phục vụ ${ipUserCount + 1}/2 tài khoản trong ngày
                                </div>
                                <p>🌐 IP: ${userIP}</p>
                                <p>⏰ Thời gian: ${currentDateTime}</p>
                                <p>🛡️ Thông tin đã được ghi nhận và báo cáo Admin!</p>
                            </div>
                        </body>
                        </html>
                    `);
                }
                
                // Bước 2: Ghi nhận thành công - cập nhật limit và log IP
                updateDailyLimit(userId, userIP, taskType);
                
                db.run(`INSERT INTO ip_logs (ip, user_id, user_agent, task_type) VALUES (?, ?, ?, ?)`, 
                        [userIP, userId, userAgent, taskType]);
                
                console.log(`[${currentDateTime}] ✅ THÀNH CÔNG! User: ${userId} | Task: ${taskType} | Thưởng: ${reward}Đ | IP: ${userIP}`);
                
                res.send(`
                    <!DOCTYPE html>
                    <html lang="vi">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
                        <title>🎉 XÁC MINH THÀNH CÔNG - NHẬN THƯỞNG NGAY!</title>
                        <style>
                            * { margin: 0; padding: 0; box-sizing: border-box; }
                            body { 
                                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                display: flex; 
                                justify-content: center; 
                                align-items: center; 
                                min-height: 100vh; 
                                padding: 15px; 
                            }
                            .container { 
                                background: #ffffff; 
                                padding: 30px 25px; 
                                border-radius: 28px; 
                                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); 
                                text-align: center; 
                                max-width: 520px; 
                                width: 100%; 
                                animation: slideUp 0.5s ease;
                            }
                            @keyframes slideUp {
                                from { opacity: 0; transform: translateY(30px); }
                                to { opacity: 1; transform: translateY(0); }
                            }
                            .icon-success { 
                                font-size: 75px; 
                                margin-bottom: 15px; 
                                animation: bounce 0.6s ease; 
                            }
                            @keyframes bounce { 
                                0%, 100% { transform: translateY(0); } 
                                50% { transform: translateY(-12px); } 
                            }
                            h2 { color: #2ed573; font-size: 28px; margin-bottom: 8px; font-weight: 700; }
                            .subtitle { color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }
                            .reward-box { 
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                padding: 18px; 
                                border-radius: 20px; 
                                margin-bottom: 25px;
                                box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                            }
                            .reward-box span { 
                                color: #ffd700; 
                                font-size: 36px; 
                                font-weight: bold; 
                                display: block; 
                                text-shadow: 0 2px 4px rgba(0,0,0,0.2);
                            }
                            .reward-box small { color: rgba(255,255,255,0.9); font-size: 13px; }
                            .task-name {
                                background: #f0f0f0;
                                padding: 8px 16px;
                                border-radius: 50px;
                                display: inline-block;
                                margin-bottom: 20px;
                                font-weight: bold;
                                color: #667eea;
                            }
                            .key-title { 
                                font-size: 12px; 
                                font-weight: bold; 
                                color: #57606f; 
                                text-transform: uppercase; 
                                text-align: left; 
                                margin-bottom: 8px; 
                                letter-spacing: 1px;
                            }
                            .key-container { 
                                display: flex; 
                                align-items: center; 
                                background: #f8f9fa; 
                                border: 2px solid #2ed573; 
                                padding: 12px 15px; 
                                border-radius: 16px; 
                                margin-bottom: 25px;
                                transition: all 0.3s;
                            }
                            .key-container:hover {
                                box-shadow: 0 5px 15px rgba(46, 213, 115, 0.2);
                            }
                            .key-text { 
                                font-family: 'Courier New', monospace; 
                                font-size: 13px; 
                                font-weight: bold; 
                                color: #ff4757; 
                                flex: 1; 
                                text-align: left; 
                                overflow-x: auto; 
                                word-break: break-all;
                                background: #fff;
                                padding: 8px 12px;
                                border-radius: 10px;
                            }
                            .copy-btn { 
                                background: linear-gradient(135deg, #2ed573 0%, #26af5f 100%);
                                color: white; 
                                border: none; 
                                padding: 10px 20px; 
                                font-size: 13px; 
                                font-weight: bold; 
                                border-radius: 12px; 
                                cursor: pointer; 
                                transition: 0.2s; 
                                margin-left: 12px;
                                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                            }
                            .copy-btn:hover { 
                                transform: scale(1.03); 
                                box-shadow: 0 5px 15px rgba(46, 213, 115, 0.3);
                            }
                            .copy-btn:active { transform: scale(0.98); }
                            .footer-info { 
                                font-size: 11px; 
                                color: #a4b0be; 
                                border-top: 1px solid #f1f2f6; 
                                padding-top: 18px; 
                                text-align: left; 
                                line-height: 1.7;
                                background: #fafbfc;
                                border-radius: 12px;
                                padding: 15px;
                            }
                            .instruction {
                                background: #e8f8f5;
                                padding: 12px;
                                border-radius: 12px;
                                margin: 20px 0;
                                font-size: 13px;
                                color: #27ae60;
                            }
                            @media (max-width: 480px) {
                                .container { padding: 25px 18px; }
                                .key-container { flex-direction: column; gap: 10px; }
                                .copy-btn { margin-left: 0; width: 100%; }
                                .key-text { width: 100%; text-align: center; }
                            }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="icon-success">🎉✨🏆</div>
                            <h2>VƯỢT LINK THÀNH CÔNG!</h2>
                            <div class="subtitle">Chúc mừng bạn đã hoàn thành nhiệm vụ</div>
                            
                            <div class="task-name">📌 ${taskType}</div>
                            
                            <div class="reward-box">
                                <span>+${reward.toLocaleString()} ₫</span>
                                <small>Đã được cộng vào tài khoản của bạn</small>
                            </div>
                            
                            <div class="instruction">
                                📋 <strong>HƯỚNG DẪN NHẬN THƯỞNG:</strong><br>
                                1️⃣ Nhấn nút COPY bên dưới<br>
                                2️⃣ Quay lại Telegram Bot<br>
                                3️⃣ Dán mã vào khung chat để nhận tiền!
                            </div>
                            
                            <div class="key-title">🔑 MÃ XÁC MINH CỦA BẠN:</div>
                            <div class="key-container">
                                <div class="key-text" id="keyText">${tokenValue}</div>
                                <button class="copy-btn" onclick="copyKeyAndDelete()">📋 COPY MÃ</button>
                            </div>
                            
                            <div class="footer-info">
                                🌐 <strong>IP:</strong> ${userIP}<br>
                                📱 <strong>Thiết bị:</strong> ${userAgent.substring(0, 45)}${userAgent.length > 45 ? '...' : ''}<br>
                                ⏰ <strong>Thời gian:</strong> ${currentDateTime}<br>
                                🛡️ <strong>Trạng thái:</strong> Đã xác minh thành công
                            </div>
                        </div>
                        <script>
                            let tokenDeleted = false;
                            
                            function deleteToken() {
                                if (tokenDeleted) return;
                                tokenDeleted = true;
                                fetch('/api/delete-token', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ token: '${tokenValue}' })
                                }).catch(err => console.log('Lỗi xóa token:', err));
                            }
                            
                            function copyKeyAndDelete() {
                                const keyText = document.getElementById("keyText").innerText;
                                navigator.clipboard.writeText(keyText).then(() => {
                                    alert("✅ Đã sao chép mã thành công!\\n\\n👉 Quay lại Bot Telegram và dán mã để nhận tiền thưởng!");
                                    deleteToken();
                                }).catch(() => {
                                    const textarea = document.createElement("textarea");
                                    textarea.value = keyText;
                                    document.body.appendChild(textarea);
                                    textarea.select();
                                    document.execCommand("copy");
                                    document.body.removeChild(textarea);
                                    alert("✅ Đã sao chép mã thành công!\\n\\n👉 Quay lại Bot Telegram và dán mã để nhận tiền thưởng!");
                                    deleteToken();
                                });
                            }
                            
                            setTimeout(function() {
                                deleteToken();
                            }, 300000);
                        </script>
                    </body>
                    </html>
                `);
            });
        });
    });
});

// API xóa token sau khi người dùng đã copy mã
app.post('/api/delete-token', (req, res) => {
    const { token } = req.body;
    if (token) {
        db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
        console.log(`[${getVietnamDateTime()}] Đã xóa token: ${token.substring(0, 10)}...`);
        res.json({ status: "deleted" });
    } else {
        res.status(400).json({ error: "Thiếu token" });
    }
});

// API kiểm tra trạng thái server
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        vietnamTime: getVietnamDateTime(),
        isTaskTime: isWithinTaskTime(),
        currentHour: getVietnamHour()
    });
});

// Xóa IP logs cũ sau 24H
setInterval(() => {
    db.run(`DELETE FROM ip_logs WHERE accessed_at <= datetime('now', '-1 day')`);
    db.run(`DELETE FROM daily_task_limit WHERE task_date < date('now')`);
    console.log(`[${getVietnamDateTime()}] 🗑️ Đã xóa logs cũ sau 24H`);
}, 3600000);

app.listen(PORT, () => console.log(`🚀 Web Verify Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
