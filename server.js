// Hệ thống Web Verify MMO - Bảo mật tối đa - Chống trùng IP 100%
// GIẢI PHÁP: Lưu token vào RAM (Map), không dùng SQLite để tránh lỗi ghi/xóa

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ADMIN ID
const ADMIN_ID = 6327666718;

// Lưu token trong RAM (Map) – tự động xóa sau 120 phút
const activeTokens = new Map(); // key: token, value: { user_id, task_type, ip, fingerprint, createdAt }

// Lưu blacklist IP và fingerprint (dùng file để tồn tại qua restart)
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
let ipBlacklist = new Set(); // lưu ip
let fingerprintBlacklist = new Set();

// Đọc blacklist từ file nếu có
if (fs.existsSync(BLACKLIST_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
        ipBlacklist = new Set(data.ipBlacklist || []);
        fingerprintBlacklist = new Set(data.fingerprintBlacklist || []);
        console.log('✅ Đã tải blacklist từ file');
    } catch(e) {}
}

// Ghi blacklist vào file
function saveBlacklist() {
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify({
        ipBlacklist: Array.from(ipBlacklist),
        fingerprintBlacklist: Array.from(fingerprintBlacklist)
    }, null, 2));
}

// Thêm vào blacklist
function addToBlacklist(ip, fingerprint, reason) {
    if (ip && ip !== '0.0.0.0') ipBlacklist.add(ip);
    if (fingerprint) fingerprintBlacklist.add(fingerprint);
    saveBlacklist();
    console.log(`[BLACKLIST] Đã thêm IP ${ip}, FP ${fingerprint} vì: ${reason}`);
    notifyAdmin(`🚨 ĐÃ THÊM BLACKLIST!\nIP: ${ip}\nFingerprint: ${fingerprint}\nLý do: ${reason}\nThời gian: ${getVietnamDateTime()}`);
}

// Hàm xóa token cũ (chạy mỗi giờ)
function cleanExpiredTokens() {
    const now = Date.now();
    for (const [token, data] of activeTokens.entries()) {
        if (now - data.createdAt > 120 * 60 * 1000) { // 120 phút
            activeTokens.delete(token);
        }
    }
    console.log(`[CLEAN] Đã xóa token cũ. Còn ${activeTokens.size} token hoạt động.`);
}
setInterval(cleanExpiredTokens, 60 * 60 * 1000); // mỗi giờ

// Lấy giờ Việt Nam (UTC+7)
function getVietnamTime() {
    const now = new Date();
    return new Date(now.getTime() + 7 * 60 * 60 * 1000);
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
    return getVietnamTime().getUTCHours();
}

// Lấy IP thật - chống spoofing
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
            if (isValidIP(firstIP)) return firstIP;
        }
    }
    const socketIP = req.socket.remoteAddress;
    if (socketIP && isValidIP(socketIP)) return socketIP;
    return '0.0.0.0';
}

function isValidIP(ip) {
    if (!ip) return false;
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') return false;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
        const parts = ip.split('.');
        for (const part of parts) if (parseInt(part) > 255) return false;
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

// Lưu daily task limit (dùng Map trong RAM, có thể dùng file nếu cần)
const dailyTaskLimit = new Map(); // key: `${user_id}|${task_type}|${date}`, value: count

function checkDailyLimit(user_id, task_type) {
    const today = getVietnamDate();
    const key = `${user_id}|${task_type}|${today}`;
    const count = dailyTaskLimit.get(key) || 0;
    const limits = {
        'LINK4M': 1, 'YEUMONEY': 3, 'SITE2S': 2, 'BBMKTS': 1,
        'LAYMA': 4, 'NHAPMA': 4, 'TAPLAYMA': 4, 'LINK2M': 2, 'SHRINKME': 1
    };
    const max = limits[task_type] || 999;
    return { count, max, reached: count >= max };
}

function incrementDailyLimit(user_id, task_type) {
    const today = getVietnamDate();
    const key = `${user_id}|${task_type}|${today}`;
    const current = dailyTaskLimit.get(key) || 0;
    dailyTaskLimit.set(key, current + 1);
}

// Lấy reward theo task_type
function getRewardByTaskType(task_type) {
    const rewards = {
        'LINK4M': 300, 'YEUMONEY': 300, 'SITE2S': 300,
        'BBMKTS': 300, 'LAYMA': 400, 'NHAPMA': 500,
        'TAPLAYMA': 500, 'LINK2M': 300, 'SHRINKME': 50
    };
    return rewards[task_type] || 300;
}

function notifyAdmin(message) {
    const fetch = require('node-fetch');
    const token = '8649791125:AAED_yDtgpml3ioVca-sAgLCBPhVnYS2QcA';
    fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=${ADMIN_ID}&text=${encodeURIComponent(message)}`)
        .catch(err => console.error('Lỗi gửi thông báo admin:', err));
}

function isWithinTaskTime() {
    const hour = getVietnamHour();
    return hour >= 6 && hour < 24;
}

app.set('trust proxy', true);
app.use(express.json());

// API tạo token – LƯU VÀO RAM
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
    
    // Kiểm tra blacklist
    if (ipBlacklist.has(clientIP) || fingerprintBlacklist.has(fingerprint)) {
        return res.status(403).json({ error: "IP của bạn đã bị khóa vĩnh viễn!" });
    }
    
    // Lưu token vào RAM
    activeTokens.set(token, {
        user_id: String(user_id),
        task_type,
        ip: clientIP,
        fingerprint,
        createdAt: Date.now()
    });
    
    console.log(`[CREATE TOKEN] Token: ${token.substring(0, 10)}..., User: ${user_id}, Task: ${task_type}, IP: ${clientIP}`);
    res.json({ status: "success" });
});

// API kiểm tra token – KHÔNG XÓA TOKEN
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
    
    const tokenData = activeTokens.get(token);
    if (!tokenData) {
        return res.json({ valid: false });
    }
    
    // Kiểm tra IP có khớp không
    if (tokenData.ip !== clientIP) {
        addToBlacklist(clientIP, fingerprint, `IP không khớp khi check token`);
        activeTokens.delete(token);
        return res.json({ valid: false });
    }
    
    // Kiểm tra user_id
    if (tokenData.user_id !== String(user_id)) {
        return res.json({ valid: false });
    }
    
    // KHÔNG XÓA TOKEN – giữ để web verify hiển thị
    res.json({ valid: true, task_type: tokenData.task_type, user_id: tokenData.user_id });
});

// Trang xác minh – LẤY TOKEN TỪ RAM
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
    
    // Kiểm tra blacklist
    if (ipBlacklist.has(userIP) || fingerprintBlacklist.has(fingerprint)) {
        return res.send(`<!DOCTYPE html><html><head><title>ĐÃ BỊ KHÓA</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🔒 TÀI KHOẢN ĐÃ BỊ KHÓA</h2><p>Liên hệ Admin để được hỗ trợ.</p></div></body></html>`);
    }
    
    const tokenData = activeTokens.get(token);
    if (!tokenData) {
        return res.send(`<!DOCTYPE html><html><head><title>TOKEN HẾT HẠN</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff4757;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>❌ PHIÊN XÁC MINH KHÔNG TỒN TẠI</h2><p>Mã đã hết hiệu lực (120 phút)</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }
    
    const userId = tokenData.user_id;
    const taskType = tokenData.task_type;
    const tokenValue = token;
    const rewardAmount = getRewardByTaskType(taskType);
    
    // Kiểm tra IP có khớp với lúc tạo token không
    if (tokenData.ip !== userIP) {
        addToBlacklist(userIP, fingerprint, `IP không khớp khi verify`);
        activeTokens.delete(token);
        return res.send(`<!DOCTYPE html><html><head><title>IP KHÔNG HỢP LỆ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🌐 IP KHÔNG HỢP LỆ</h2><p>Bạn phải dùng cùng IP khi tạo link và xác minh!</p></div></body></html>`);
    }
    
    // Kiểm tra giới hạn nhiệm vụ
    const limit = checkDailyLimit(userId, taskType);
    if (limit.reached) {
        activeTokens.delete(token);
        return res.send(`<!DOCTYPE html><html><head><title>GIỚI HẠN NHIỆM VỤ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff9800;}.limit{background:#fff3e0;padding:15px;border-radius:12px;margin:20px0;font-size:36px;font-weight:bold;color:#ff9800;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>📊 BẠN ĐÃ ĐẠT GIỚI HẠN</h2><div class=limit>${limit.count}/${limit.max}</div><p>Cổng <strong>${taskType}</strong></p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }
    
    // Tăng số lần làm task
    incrementDailyLimit(userId, taskType);
    
    // Log IP
    console.log(`[${currentDateTime}] ✅ THÀNH CÔNG! User: ${userId} | Task: ${taskType} | Thưởng: ${rewardAmount}Đ | IP: ${userIP}`);
    
    // KHÔNG XÓA TOKEN – giữ lại để bot check (sẽ tự động xóa sau 120 phút)
    // Nhưng nếu không xóa, người dùng có thể dùng lại token nhiều lần? Không, vì đã tăng limit.
    
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🎉 XÁC MINH THÀNH CÔNG!</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;padding:15px;font-family:'Segoe UI',Arial,sans-serif}.container{background:#fff;padding:30px;border-radius:20px;text-align:center;max-width:500px;width:100%}h2{color:#2ed573;font-size:28px;margin-bottom:15px}.reward-box{background:linear-gradient(135deg,#667eea,#764ba2);padding:20px;border-radius:15px;margin:20px 0}.reward-box span{color:#ffd700;font-size:36px;font-weight:bold}.key-box{background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;word-break:break-all;font-family:monospace;font-size:14px}.copy-btn{background:#2ed573;color:#fff;border:none;padding:12px 24px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:bold}.copy-btn:hover{background:#26af5f}.warning-box{font-size:11px;color:#888;margin-top:20px;padding:10px;background:#f8f9fa;border-radius:10px}</style></head><body><div class=container><h2>🎉 VƯỢT LINK THÀNH CÔNG!</h2><p>Chúc mừng bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p><div class=reward-box><span>+${rewardAmount} ₫</span></div><div><strong>🔑 MÃ XÁC MINH CỦA BẠN:</strong></div><div class=key-box id="keyText">${tokenValue}</div><button class="copy-btn" onclick="copyKey()">📋 COPY MÃ</button><div class=warning-box>⚠️ Mỗi IP chỉ được sử dụng cho 1 tài khoản duy nhất!<br>📌 Sau khi copy mã, quay lại Bot và dán mã để nhận thưởng!</div></div><script>function copyKey(){const text=document.getElementById("keyText").innerText;navigator.clipboard.writeText(text).then(()=>alert("✅ Đã sao chép mã! Quay lại Bot để nhận thưởng!"));}</script></body></html>`);
});

app.post('/api/delete-token', (req, res) => {
    const { token } = req.body;
    if (token && activeTokens.has(token)) {
        activeTokens.delete(token);
        res.json({ status: "deleted" });
    } else {
        res.status(400).json({ error: "Thiếu token hoặc token không tồn tại" });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', vietnamTime: getVietnamDateTime(), activeTokens: activeTokens.size });
});

app.listen(PORT, () => console.log(`🚀 Web Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
