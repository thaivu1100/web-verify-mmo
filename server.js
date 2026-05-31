// Hệ thống Web Verify MMO - Bảo mật tối đa - Chống trùng IP 100%
// Lưu token vào RAM + file backup để chống mất token khi restart

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ADMIN ID
const ADMIN_ID = 6327666718;

// File lưu token backup
const TOKENS_BACKUP_FILE = path.join(__dirname, 'tokens_backup.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');

// Lưu token trong RAM (Map)
let activeTokens = new Map(); // key: token, value: { user_id, task_type, ip, fingerprint, createdAt }

// Lưu blacklist
let ipBlacklist = new Set();
let fingerprintBlacklist = new Set();

// Lưu IP usage trong ngày (1 IP/ngày chỉ 1 user)
let ipUsageToday = new Map(); // key: ip, value: { user_id, date }

// Lưu daily task limit (cho phép reset mỗi ngày)
let dailyTaskLimit = new Map(); // key: `${user_id}|${task_type}|${date}`, value: count

// Hàm backup token ra file
function backupTokens() {
    const tokensObj = {};
    for (const [token, data] of activeTokens.entries()) {
        tokensObj[token] = data;
    }
    fs.writeFileSync(TOKENS_BACKUP_FILE, JSON.stringify(tokensObj, null, 2));
    console.log(`[BACKUP] Đã backup ${activeTokens.size} tokens`);
}

// Hàm khôi phục token từ file
function restoreTokens() {
    if (fs.existsSync(TOKENS_BACKUP_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(TOKENS_BACKUP_FILE, 'utf8'));
            const now = Date.now();
            let restored = 0;
            for (const [token, tokenData] of Object.entries(data)) {
                if (now - tokenData.createdAt <= 120 * 60 * 1000) { // còn hạn
                    activeTokens.set(token, tokenData);
                    restored++;
                }
            }
            console.log(`[RESTORE] Đã khôi phục ${restored} token còn hạn`);
        } catch(e) { console.error('Lỗi đọc backup token:', e); }
    }
}

// Backup mỗi 10 giây
setInterval(() => {
    if (activeTokens.size > 0) backupTokens();
}, 10000);

// Khôi phục khi khởi động
restoreTokens();

// Đọc blacklist
if (fs.existsSync(BLACKLIST_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
        ipBlacklist = new Set(data.ipBlacklist || []);
        fingerprintBlacklist = new Set(data.fingerprintBlacklist || []);
        console.log('✅ Đã tải blacklist từ file');
    } catch(e) {}
}

function saveBlacklist() {
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify({
        ipBlacklist: Array.from(ipBlacklist),
        fingerprintBlacklist: Array.from(fingerprintBlacklist)
    }, null, 2));
}

// Lấy giờ Việt Nam
function getVietnamTime() {
    const now = new Date();
    return new Date(now.getTime() + 7 * 60 * 60 * 1000);
}
function getVietnamDate() {
    const vt = getVietnamTime();
    const y = vt.getUTCFullYear();
    const m = String(vt.getUTCMonth() + 1).padStart(2, '0');
    const d = String(vt.getUTCDate()).padStart(2, '0');
    return `${d}-${m}-${y}`;
}
function getVietnamDateTime() {
    const vt = getVietnamTime();
    const y = vt.getUTCFullYear();
    const m = String(vt.getUTCMonth() + 1).padStart(2, '0');
    const d = String(vt.getUTCDate()).padStart(2, '0');
    const h = String(vt.getUTCHours()).padStart(2, '0');
    const min = String(vt.getUTCMinutes()).padStart(2, '0');
    const s = String(vt.getUTCSeconds()).padStart(2, '0');
    return `${d}-${m}-${y} ${h}:${min}:${s}`;
}
function getVietnamHour() {
    return getVietnamTime().getUTCHours();
}

// Lấy IP thật
function getRealIP(req) {
    const headers = ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for', 'x-client-ip', 'x-cluster-client-ip', 'forwarded-for', 'forwarded'];
    for (const h of headers) {
        const ip = req.headers[h];
        if (ip && typeof ip === 'string') {
            const first = ip.split(',')[0].trim();
            if (isValidIP(first)) return first;
        }
    }
    const socketIP = req.socket.remoteAddress;
    if (socketIP && isValidIP(socketIP)) return socketIP;
    return '0.0.0.0';
}
function isValidIP(ip) {
    if (!ip) return false;
    if (ip === '::1' || ip === '127.0.0.1' || ip === 'localhost') return false;
    const regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!regex.test(ip)) return false;
    return ip.split('.').every(p => parseInt(p) <= 255);
}
function generateDeviceFingerprint(req) {
    const ua = req.headers['user-agent'] || 'Unknown';
    const lang = req.headers['accept-language'] || 'Unknown';
    const platform = req.headers['sec-ch-ua-platform'] || 'Unknown';
    const data = `${ua}|${lang}|${platform}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 32);
}

function getRewardByTaskType(task_type) {
    const map = { 'LINK4M':300, 'YEUMONEY':300, 'SITE2S':300, 'BBMKTS':300, 'LAYMA':400, 'NHAPMA':500, 'TAPLAYMA':500, 'LINK2M':300, 'SHRINKME':50 };
    return map[task_type] || 300;
}

function addToBlacklist(ip, fingerprint, reason) {
    if (ip && ip !== '0.0.0.0') ipBlacklist.add(ip);
    if (fingerprint) fingerprintBlacklist.add(fingerprint);
    saveBlacklist();
    console.log(`[BLACKLIST] ${ip} / ${fingerprint} - ${reason}`);
    notifyAdmin(`🚨 BLACKLIST: ${ip}\n${reason}`);
}

function notifyAdmin(msg) {
    const fetch = require('node-fetch');
    const token = '8649791125:AAED_yDtgpml3ioVca-sAgLCBPhVnYS2QcA';
    fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=${ADMIN_ID}&text=${encodeURIComponent(msg)}`)
        .catch(e => console.error(e));
}

// Dọn token cũ mỗi giờ
setInterval(() => {
    const now = Date.now();
    let deleted = 0;
    for (const [token, data] of activeTokens.entries()) {
        if (now - data.createdAt > 120 * 60 * 1000) {
            activeTokens.delete(token);
            deleted++;
        }
    }
    if (deleted > 0) {
        backupTokens();
        console.log(`[CLEAN] Đã xóa ${deleted} token cũ`);
    }
}, 60 * 60 * 1000);

// Dọn ipUsageToday theo ngày
setInterval(() => {
    const today = getVietnamDate();
    for (const [ip, data] of ipUsageToday.entries()) {
        if (data.date !== today) ipUsageToday.delete(ip);
    }
}, 60 * 60 * 1000);

// Dọn dailyTaskLimit theo ngày
setInterval(() => {
    const today = getVietnamDate();
    for (const [key, val] of dailyTaskLimit.entries()) {
        if (!key.endsWith(today)) dailyTaskLimit.delete(key);
    }
}, 60 * 60 * 1000);

app.set('trust proxy', true);
app.use(express.json());

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

    if (ipBlacklist.has(clientIP) || fingerprintBlacklist.has(fingerprint)) {
        return res.status(403).json({ error: "IP đã bị khóa vĩnh viễn!" });
    }

    // Lưu token
    activeTokens.set(token, {
        user_id: String(user_id),
        task_type,
        ip: clientIP,
        fingerprint,
        createdAt: Date.now()
    });
    backupTokens();
    console.log(`[CREATE] Token ${token.substring(0,10)}... User ${user_id} Task ${task_type} IP ${clientIP}`);
    res.json({ status: "success" });
});

// API kiểm tra token (cho bot) – KHÔNG XÓA TOKEN
app.post('/api/check-token', (req, res) => {
    const { secret_key, token, user_id } = req.body;
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") {
        return res.status(403).json({ error: "Sai Secret Key" });
    }
    if (!token || !user_id) {
        return res.status(400).json({ error: "Thiếu thông tin" });
    }
    const tokenData = activeTokens.get(token);
    if (!tokenData || tokenData.user_id !== String(user_id)) {
        return res.json({ valid: false });
    }
    // KHÔNG XÓA TOKEN
    res.json({ valid: true, task_type: tokenData.task_type, user_id: tokenData.user_id });
});

// Trang xác minh
app.get('/verify/:token', async (req, res) => {
    const token = req.params.token;
    const userIP = getRealIP(req);
    const fingerprint = generateDeviceFingerprint(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const now = getVietnamDateTime();

    console.log(`[${now}] Verify ${token.substring(0,10)}... IP ${userIP}`);

    if (getVietnamHour() < 6 || getVietnamHour() >= 24) {
        return res.send(`<!DOCTYPE html><html><head><title>HẾT GIỜ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff4757;}</style></head><body><div class=container><h2>⏰ ĐÃ HẾT GIỜ LÀM VIỆC</h2><p>6:00 - 24:00</p><p>✨ Quay lại từ 6:00 sáng!</p></div></body></html>`);
    }

    if (ipBlacklist.has(userIP) || fingerprintBlacklist.has(fingerprint)) {
        return res.send(`<!DOCTYPE html><html><head><title>ĐÃ BỊ KHÓA</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🔒 TÀI KHOẢN ĐÃ BỊ KHÓA</h2><p>Liên hệ Admin.</p></div></body></html>`);
    }

    const tokenData = activeTokens.get(token);
    if (!tokenData) {
        return res.send(`<!DOCTYPE html><html><head><title>TOKEN HẾT HẠN</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff4757;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>❌ PHIÊN XÁC MINH KHÔNG TỒN TẠI</h2><p>Mã đã hết hiệu lực (120 phút)</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }

    const userId = tokenData.user_id;
    const taskType = tokenData.task_type;
    const tokenValue = token;

    // Kiểm tra IP khớp
    if (tokenData.ip !== userIP) {
        addToBlacklist(userIP, fingerprint, `IP không khớp khi verify (token IP: ${tokenData.ip})`);
        activeTokens.delete(token);
        backupTokens();
        return res.send(`<!DOCTYPE html><html><head><title>IP KHÔNG HỢP LỆ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🌐 IP KHÔNG HỢP LỆ</h2><p>Bạn phải dùng cùng IP khi tạo link và xác minh!</p></div></body></html>`);
    }

    // Kiểm tra IP đã dùng cho user khác chưa
    const today = getVietnamDate();
    const ipRecord = ipUsageToday.get(userIP);
    if (ipRecord && ipRecord.user_id !== userId && ipRecord.date === today) {
        addToBlacklist(userIP, fingerprint, `IP đã dùng cho user ${ipRecord.user_id} khác`);
        activeTokens.delete(token);
        backupTokens();
        return res.send(`<!DOCTYPE html><html><head><title>TRÙNG IP</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}.warning{background:#ffeaa7;padding:15px;border-radius:12px;margin:20px0;}</style></head><body><div class=container><h2>🚫 IP ĐÃ ĐƯỢC SỬ DỤNG</h2><div class=warning>IP ${userIP} đã được sử dụng bởi tài khoản khác trong ngày hôm nay!<br>Mỗi IP chỉ được dùng cho 1 tài khoản duy nhất.</div><p>⏰ ${now}</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }
    ipUsageToday.set(userIP, { user_id: userId, date: today });

    // Kiểm tra giới hạn nhiệm vụ
    const limitKey = `${userId}|${taskType}|${today}`;
    let count = dailyTaskLimit.get(limitKey) || 0;
    const limits = { 'LINK4M':1, 'YEUMONEY':3, 'SITE2S':2, 'BBMKTS':1, 'LAYMA':4, 'NHAPMA':4, 'TAPLAYMA':4, 'LINK2M':2, 'SHRINKME':1 };
    const max = limits[taskType] || 999;
    if (count >= max) {
        activeTokens.delete(token);
        backupTokens();
        return res.send(`<!DOCTYPE html><html><head><title>GIỚI HẠN NHIỆM VỤ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff9800;}.limit{background:#fff3e0;padding:15px;border-radius:12px;margin:20px0;font-size:36px;font-weight:bold;color:#ff9800;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>📊 BẠN ĐÃ ĐẠT GIỚI HẠN</h2><div class=limit>${count}/${max}</div><p>Cổng <strong>${taskType}</strong></p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }
    dailyTaskLimit.set(limitKey, count + 1);

    // Log
    console.log(`[${now}] ✅ SUCCESS User ${userId} Task ${taskType} +${getRewardByTaskType(taskType)}Đ IP ${userIP}`);

    // KHÔNG XÓA TOKEN – giữ lại
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🎉 XÁC MINH THÀNH CÔNG!</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;padding:15px;font-family:'Segoe UI',Arial,sans-serif}.container{background:#fff;padding:30px;border-radius:20px;text-align:center;max-width:500px;width:100%}h2{color:#2ed573;font-size:28px;margin-bottom:15px}.reward-box{background:linear-gradient(135deg,#667eea,#764ba2);padding:20px;border-radius:15px;margin:20px 0}.reward-box span{color:#ffd700;font-size:36px;font-weight:bold}.key-box{background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;word-break:break-all;font-family:monospace;font-size:14px}.copy-btn{background:#2ed573;color:#fff;border:none;padding:12px 24px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:bold}.copy-btn:hover{background:#26af5f}.warning-box{font-size:11px;color:#888;margin-top:20px;padding:10px;background:#f8f9fa;border-radius:10px}</style></head><body><div class=container><h2>🎉 VƯỢT LINK THÀNH CÔNG!</h2><p>Chúc mừng bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p><div class=reward-box><span>+${getRewardByTaskType(taskType)} ₫</span></div><div><strong>🔑 MÃ XÁC MINH CỦA BẠN:</strong></div><div class=key-box id="keyText">${tokenValue}</div><button class="copy-btn" onclick="copyKey()">📋 COPY MÃ</button><div class=warning-box>⚠️ Mỗi IP chỉ được sử dụng cho 1 tài khoản duy nhất!<br>📌 Sau khi copy mã, quay lại Bot và dán mã để nhận thưởng!</div></div><script>function copyKey(){const text=document.getElementById("keyText").innerText;navigator.clipboard.writeText(text).then(()=>alert("✅ Đã sao chép mã! Quay lại Bot để nhận thưởng!"));}</script></body></html>`);
});

app.post('/api/delete-token', (req, res) => {
    const { token } = req.body;
    if (token && activeTokens.has(token)) {
        activeTokens.delete(token);
        backupTokens();
        res.json({ status: "deleted" });
    } else {
        res.status(400).json({ error: "Thiếu token hoặc token không tồn tại" });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', vietnamTime: getVietnamDateTime(), activeTokens: activeTokens.size });
});

app.listen(PORT, () => console.log(`🚀 Web Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
