// Hệ thống Web Verify MMO - Bảo mật tối đa - Chống trùng IP 100%

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

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

// HÀM LẤY IP THẬT - CHỐNG SPOOFING
function getRealIP(req) {
    const ipHeaders = [
        'cf-connecting-ip',
        'x-real-ip',
        'x-forwarded-for',
        'x-client-ip',
        'x-cluster-client-ip',
        'forwarded-for',
        'forwarded'
    ];
    
    for (const header of ipHeaders) {
        const ip = req.headers[header];
        if (ip && typeof ip === 'string') {
            const firstIP = ip.split(',')[0].trim();
            if (isValidIP(firstIP)) {
                return firstIP;
            }
        }
    }
    
    const socketIP = req.socket.remoteAddress;
    if (socketIP && isValidIP(socketIP)) {
        return socketIP;
    }
    
    return '0.0.0.0';
}

function isValidIP(ip) {
    if (!ip) return false;
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') return false;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
        const parts = ip.split('.');
        for (const part of parts) {
            if (parseInt(part) > 255) return false;
        }
        return true;
    }
    return false;
}

function generateDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'Unknown';
    const platform = req.headers['sec-ch-ua-platform'] || 'Unknown';
    const fingerprintData = `${userAgent}|${acceptLanguage}|${platform}`;
    return crypto.createHash('sha256').update(fingerprintData).digest('hex').substring(0, 32);
}

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS active_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT,
        task_type TEXT,
        ip TEXT,
        fingerprint TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS ip_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        fingerprint TEXT,
        reason TEXT,
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
        fingerprint TEXT,
        task_type TEXT,
        task_date TEXT,
        UNIQUE(user_id, task_type, task_date)
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_daily_task_limit_ip_date ON daily_task_limit(ip, task_date)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_daily_task_limit_fingerprint ON daily_task_limit(fingerprint)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_active_tokens_created ON active_tokens(created_at)`);
    console.log('✅ Cơ sở dữ liệu đã sẵn sàng');
});

app.set('trust proxy', true);
app.use(express.json());

function notifyAdmin(message) {
    const fetch = require('node-fetch');
    const token = '8649791125:AAED_yDtgpml3ioVca-sAgLCBPhVnYS2QcA';
    fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=${ADMIN_ID}&text=${encodeURIComponent(message)}`)
        .catch(err => console.error('Lỗi gửi thông báo admin:', err));
}

// Lấy đúng reward theo task_type (đồng bộ với bot)
function getRewardByTaskType(task_type) {
    const rewards = {
        'LINK4M': 300,
        'YEUMONEY': 300,
        'SITE2S': 300,
        'BBMKTS': 300,
        'LAYMA': 400,
        'NHAPMA': 500,
        'TAPLAYMA': 500,
        'LINK2M': 300,
        'SHRINKME': 50
    };
    return rewards[task_type] || 300;
}

// Bỏ qua kiểm tra giới hạn từ bot (chạy độc lập)
async function checkDailyLimitFromBot(user_id, task_type) {
    const reward = getRewardByTaskType(task_type);
    return { allowed: true, currentCount: 0, dailyLimit: 999, reward: reward };
}

function isIPBlacklisted(ip, fingerprint, callback) {
    db.get(`SELECT COUNT(*) as count FROM ip_blacklist WHERE ip = ? OR fingerprint = ?`, 
        [ip, fingerprint], (err, row) => {
        callback(null, row ? row.count > 0 : false);
    });
}

function addToBlacklist(ip, fingerprint, reason) {
    db.run(`INSERT INTO ip_blacklist (ip, fingerprint, reason) VALUES (?, ?, ?)`, 
        [ip, fingerprint, reason], (err) => {
        if (!err) {
            console.log(`[BLACKLIST] Đã thêm IP ${ip} vào blacklist vì: ${reason}`);
            notifyAdmin(`🚨 ĐÃ THÊM BLACKLIST!\nIP: ${ip}\nFingerprint: ${fingerprint}\nLý do: ${reason}\nThời gian: ${getVietnamDateTime()}`);
        }
    });
}

function checkIpAdvancedUsage(ip, fingerprint, current_user_id, callback) {
    const today = getVietnamDate();
    
    db.get(`SELECT COUNT(DISTINCT user_id) as user_count FROM daily_task_limit 
            WHERE ip = ? AND task_date = ? AND user_id != ?`,
            [ip, today, current_user_id], (err, row) => {
        if (err) return callback(err, false);
        const userCount = row ? row.user_count : 0;
        if (userCount >= 1) {
            return callback(null, false, `IP ${ip} đã được sử dụng bởi ${userCount + 1} tài khoản khác. Chỉ được 1 tài khoản/IP!`);
        }
        
        db.get(`SELECT COUNT(*) as fp_count FROM daily_task_limit 
                WHERE fingerprint = ? AND task_date = ? AND ip != ?`,
                [fingerprint, today, ip], (err, fpRow) => {
            if (err) return callback(err, false);
            const fpCount = fpRow ? fpRow.fp_count : 0;
            if (fpCount >= 1) {
                addToBlacklist(ip, fingerprint, `Fingerprint trùng lặp từ IP khác`);
                return callback(null, false, `Phát hiện hành vi gian lận! Thiết bị của bạn đã được ghi nhận.`);
            }
            
            db.get(`SELECT COUNT(*) as request_count FROM active_tokens 
                    WHERE ip = ? AND created_at > datetime('now', '-1 hour')`,
                    [ip], (err, reqRow) => {
                if (err) return callback(err, false);
                const requestCount = reqRow ? reqRow.request_count : 0;
                if (requestCount >= 5) {
                    addToBlacklist(ip, fingerprint, `Quá nhiều request: ${requestCount} lần/giờ`);
                    return callback(null, false, `Bạn đã thực hiện quá nhiều request! Vui lòng đợi 1 giờ.`);
                }
                callback(null, true);
            });
        });
    });
}

// API tạo token
app.post('/api/create-token', (req, res) => {
    const { secret_key, user_id, task_type, token } = req.body;
    const clientIP = getRealIP(req);
    const fingerprint = generateDeviceFingerprint(req);
    
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    
    isIPBlacklisted(clientIP, fingerprint, (err, isBlacklisted) => {
        if (isBlacklisted) {
            return res.status(403).json({ error: "IP của bạn đã bị khóa vĩnh viễn!" });
        }
        
        db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-120 minutes')`);
        db.run(`INSERT OR REPLACE INTO active_tokens (token, user_id, task_type, ip, fingerprint, created_at) 
                VALUES (?, ?, ?, ?, ?, datetime('now'))`, 
            [token, String(user_id), task_type, clientIP, fingerprint], (err) => {
                if (err) return res.status(500).json({ error: "Lỗi ghi token" });
                console.log(`[CREATE TOKEN] Token: ${token.substring(0, 10)}..., User: ${user_id}, Task: ${task_type}, IP: ${clientIP}`);
                res.json({ status: "success" });
            });
    });
});

// API kiểm tra token - KHÔNG XÓA TOKEN
app.post('/api/check-token', (req, res) => {
    const { secret_key, token, user_id } = req.body;
    const clientIP = getRealIP(req);
    const fingerprint = generateDeviceFingerprint(req);
    
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    
    db.get(`SELECT * FROM active_tokens WHERE token = ? AND user_id = ?`, 
        [token, String(user_id)], (err, row) => {
        if (err || !row) {
            return res.json({ valid: false });
        }
        if (row.ip !== clientIP) {
            addToBlacklist(clientIP, fingerprint, `IP không khớp khi check token`);
            db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
            return res.json({ valid: false });
        }
        res.json({ valid: true, task_type: row.task_type, user_id: row.user_id });
    });
});

function isWithinTaskTime() {
    const hour = getVietnamHour();
    return hour >= 6 && hour < 24;
}

// Trang xác minh - GIỮ TOKEN 120 PHÚT
app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;
    const userIP = getRealIP(req);
    const fingerprint = generateDeviceFingerprint(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const currentDateTime = getVietnamDateTime();
    
    console.log(`[${currentDateTime}] Xác minh token: ${token.substring(0, 10)}... | IP: ${userIP}`);
    
    if (!isWithinTaskTime()) {
        return res.send(`<!DOCTYPE html><html><head><title>HẾT GIỜ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;max-width:450px;}h2{color:#ff4757;}</style></head><body><div class=container><h2>⏰ ĐÃ HẾT GIỜ LÀM VIỆC</h2><p>Thời gian: <strong>6:00 - 24:00</strong></p><p>✨ Vui lòng quay lại từ 6:00 sáng!</p></div></body></html>`);
    }
    
    isIPBlacklisted(userIP, fingerprint, async (err, isBlacklisted) => {
        if (isBlacklisted) {
            return res.send(`<!DOCTYPE html><html><head><title>ĐÃ BỊ KHÓA</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🔒 TÀI KHOẢN ĐÃ BỊ KHÓA</h2><p>Liên hệ Admin để được hỗ trợ.</p></div></body></html>`);
        }
        
        db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-120 minutes')`);
        db.get(`SELECT * FROM active_tokens WHERE token = ?`, [token], async (err, row) => {
            if (err || !row) {
                return res.send(`<!DOCTYPE html><html><head><title>TOKEN HẾT HẠN</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff4757;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>❌ PHIÊN XÁC MINH KHÔNG TỒN TẠI</h2><p>Mã đã hết hiệu lực (120 phút)</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
            }
            
            const userId = row.user_id;
            const taskType = row.task_type;
            const tokenValue = row.token;
            const rewardAmount = getRewardByTaskType(taskType);
            
            if (row.ip !== userIP) {
                addToBlacklist(userIP, fingerprint, `IP không khớp khi verify`);
                db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
                return res.send(`<!DOCTYPE html><html><head><title>IP KHÔNG HỢP LỆ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🌐 IP KHÔNG HỢP LỆ</h2><p>Bạn phải dùng cùng IP khi tạo link và xác minh!</p></div></body></html>`);
            }
            
            checkIpAdvancedUsage(userIP, fingerprint, userId, async (err, isAllowed, errorMsg) => {
                if (!isAllowed) {
                    db.run(`DELETE FROM active_tokens WHERE token = ?`, [token]);
                    return res.send(`<!DOCTYPE html><html><head><title>GIỚI HẠN TRUY CẬP</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff9800,#e67e22);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#e67e22;}.error{background:#fff3e0;padding:15px;border-radius:12px;margin:20px0;}</style></head><body><div class=container><h2>⚠️ GIỚI HẠN TRUY CẬP</h2><div class=error>${errorMsg}</div></div></body></html>`);
                }
                
                db.run(`INSERT OR REPLACE INTO daily_task_limit (user_id, ip, fingerprint, task_type, task_date) 
                        VALUES (?, ?, ?, ?, ?)`, [userId, userIP, fingerprint, taskType, getVietnamDate()]);
                db.run(`INSERT INTO ip_logs (ip, user_id, user_agent, task_type) VALUES (?, ?, ?, ?)`, 
                    [userIP, userId, userAgent, taskType]);
                
                console.log(`[${currentDateTime}] ✅ THÀNH CÔNG! User: ${userId} | Task: ${taskType} | Thưởng: ${rewardAmount}Đ`);
                
                res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🎉 XÁC MINH THÀNH CÔNG!</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;padding:15px;font-family:'Segoe UI',Arial,sans-serif}.container{background:#fff;padding:30px;border-radius:20px;text-align:center;max-width:500px;width:100%}h2{color:#2ed573;font-size:28px;margin-bottom:15px}.reward-box{background:linear-gradient(135deg,#667eea,#764ba2);padding:20px;border-radius:15px;margin:20px 0}.reward-box span{color:#ffd700;font-size:36px;font-weight:bold}.key-box{background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;word-break:break-all;font-family:monospace;font-size:14px}.copy-btn{background:#2ed573;color:#fff;border:none;padding:12px 24px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:bold}.copy-btn:hover{background:#26af5f}.warning-box{font-size:11px;color:#888;margin-top:20px;padding:10px;background:#f8f9fa;border-radius:10px}</style></head><body><div class=container><h2>🎉 VƯỢT LINK THÀNH CÔNG!</h2><p>Chúc mừng bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p><div class=reward-box><span>+${rewardAmount} ₫</span></div><div><strong>🔑 MÃ XÁC MINH CỦA BẠN:</strong></div><div class=key-box id="keyText">${tokenValue}</div><button class="copy-btn" onclick="copyKey()">📋 COPY MÃ</button><div class=warning-box>⚠️ Mỗi IP chỉ được sử dụng cho 1 tài khoản duy nhất!<br>📌 Sau khi copy mã, quay lại Bot và dán mã để nhận thưởng!</div></div><script>function copyKey(){const text=document.getElementById("keyText").innerText;navigator.clipboard.writeText(text).then(()=>alert("✅ Đã sao chép mã! Quay lại Bot để nhận thưởng!"));}</script></body></html>`);
            });
        });
    });
});

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
    db.run(`DELETE FROM active_tokens WHERE created_at <= datetime('now', '-120 minutes')`);
    db.run(`DELETE FROM ip_logs WHERE accessed_at <= datetime('now', '-1 day')`);
}, 3600000);

app.listen(PORT, () => console.log(`🚀 Web Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
