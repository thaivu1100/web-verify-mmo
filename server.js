// Hệ thống Web Verify MMO - Dùng PostgreSQL để đồng bộ token giữa nhiều instance
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_ID = 6327666718;

// Lấy connection string từ biến môi trường (Render tự động set)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }  // Bắt buộc với Render
});

// Tạo bảng nếu chưa có
pool.query(`
    CREATE TABLE IF NOT EXISTS active_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        task_type TEXT NOT NULL,
        ip TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ip_blacklist (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        fingerprint TEXT,
        reason TEXT,
        time TEXT
    );
    CREATE TABLE IF NOT EXISTS ip_usage (
        ip TEXT PRIMARY KEY,
        user_id TEXT,
        date TEXT
    );
    CREATE TABLE IF NOT EXISTS ip_logs (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        user_id TEXT,
        user_agent TEXT,
        task_type TEXT,
        time TEXT
    );
`).catch(e => console.error('Lỗi tạo bảng:', e));

// Lấy giờ Việt Nam
function getVietnamTime() { const now = new Date(); return new Date(now.getTime() + 7*60*60*1000); }
function getVietnamDate() { const vt = getVietnamTime(); return `${String(vt.getUTCDate()).padStart(2,'0')}-${String(vt.getUTCMonth()+1).padStart(2,'0')}-${vt.getUTCFullYear()}`; }
function getVietnamDateTime() { const vt = getVietnamTime(); return `${getVietnamDate()} ${String(vt.getUTCHours()).padStart(2,'0')}:${String(vt.getUTCMinutes()).padStart(2,'0')}:${String(vt.getUTCSeconds()).padStart(2,'0')}`; }
function getVietnamHour() { return getVietnamTime().getUTCHours(); }

// Lấy IP thật
function getRealIP(req) {
    const headers = ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for', 'x-client-ip', 'x-cluster-client-ip', 'forwarded-for', 'forwarded'];
    for (const h of headers) {
        const ip = req.headers[h];
        if (ip && typeof ip === 'string') {
            const first = ip.split(',')[0].trim();
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(first) && !first.startsWith('127.') && first !== '0.0.0.0') return first;
        }
    }
    const socketIP = req.socket.remoteAddress;
    if (socketIP && socketIP !== '::1' && socketIP !== '127.0.0.1') return socketIP;
    return '0.0.0.0';
}

function generateDeviceFingerprint(req) {
    const ua = req.headers['user-agent'] || 'Unknown';
    const lang = req.headers['accept-language'] || 'Unknown';
    const platform = req.headers['sec-ch-ua-platform'] || 'Unknown';
    return crypto.createHash('sha256').update(`${ua}|${lang}|${platform}`).digest('hex').substring(0, 32);
}

function getRewardByTaskType(t) {
    const r = { LINK4M:300, YEUMONEY:300, SITE2S:300, BBMKTS:300, LAYMA:400, NHAPMA:500, TAPLAYMA:500, LINK2M:300, SHRINKME:50 };
    return r[t] || 300;
}

// Xóa token cũ mỗi giờ (token quá 24h)
setInterval(async () => {
    const now = Date.now();
    await pool.query('DELETE FROM active_tokens WHERE created_at < $1', [now - 24*60*60*1000]);
    console.log('[CLEAN] Đã xóa token cũ');
}, 60*60*1000);

app.set('trust proxy', true);
app.use(express.json());

// API tạo token
app.post('/api/create-token', async (req, res) => {
    const { secret_key, user_id, task_type, token } = req.body;
    const clientIP = getRealIP(req);
    const fingerprint = generateDeviceFingerprint(req);
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") return res.status(403).json({ error: "Sai Secret Key" });
    if (!token || !user_id) return res.status(400).json({ error: "Thiếu thông tin" });

    // Kiểm tra blacklist
    const blacklist = await pool.query('SELECT 1 FROM ip_blacklist WHERE ip = $1 OR fingerprint = $2', [clientIP, fingerprint]);
    if (blacklist.rows.length) return res.status(403).json({ error: "IP đã bị khóa vĩnh viễn!" });

    // Lưu token
    await pool.query(
        'INSERT INTO active_tokens (token, user_id, task_type, ip, fingerprint, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, task_type = EXCLUDED.task_type, ip = EXCLUDED.ip, fingerprint = EXCLUDED.fingerprint, created_at = EXCLUDED.created_at',
        [token, String(user_id), task_type, clientIP, fingerprint, Date.now()]
    );
    console.log(`[CREATE] Token ${token.substring(0,10)}... User ${user_id} Task ${task_type} IP ${clientIP}`);
    res.json({ status: "success" });
});

// API kiểm tra token (cho bot) – KHÔNG XÓA TOKEN
app.post('/api/check-token', async (req, res) => {
    const { secret_key, token, user_id } = req.body;
    if (secret_key !== "MY_SUPER_SECRET_PASSPHRASE_123") return res.status(403).json({ error: "Sai Secret Key" });
    if (!token || !user_id) return res.status(400).json({ error: "Thiếu thông tin" });
    const result = await pool.query('SELECT task_type FROM active_tokens WHERE token = $1 AND user_id = $2', [token, String(user_id)]);
    if (result.rows.length === 0) return res.json({ valid: false });
    res.json({ valid: true, task_type: result.rows[0].task_type, user_id: String(user_id) });
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

    // Blacklist
    const blacklist = await pool.query('SELECT 1 FROM ip_blacklist WHERE ip = $1 OR fingerprint = $2', [userIP, fingerprint]);
    if (blacklist.rows.length) {
        return res.send(`<!DOCTYPE html><html><head><title>ĐÃ BỊ KHÓA</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🔒 TÀI KHOẢN ĐÃ BỊ KHÓA</h2><p>Liên hệ Admin.</p></div></body></html>`);
    }

    // Lấy token
    const result = await pool.query('SELECT * FROM active_tokens WHERE token = $1', [token]);
    if (result.rows.length === 0) {
        console.log(`[${now}] Token ${token.substring(0,10)} NOT FOUND`);
        return res.send(`<!DOCTYPE html><html><head><title>TOKEN HẾT HẠN</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#ff4757;}a{display:inline-block;margin-top:20px;padding:12px24px;background:#667eea;color:#fff;text-decoration:none;border-radius:10px;}</style></head><body><div class=container><h2>❌ PHIÊN XÁC MINH KHÔNG TỒN TẠI</h2><p>Mã đã hết hiệu lực (24h).</p><p>Vui lòng quay lại Bot và thử lại nhiệm vụ.</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }

    const tokenData = result.rows[0];
    const userId = tokenData.user_id;
    const taskType = tokenData.task_type;
    const tokenValue = token;

    // Kiểm tra IP khớp
    if (tokenData.ip !== userIP) {
        await pool.query('INSERT INTO ip_blacklist (ip, fingerprint, reason, time) VALUES ($1, $2, $3, $4)', [userIP, fingerprint, `IP không khớp (token IP: ${tokenData.ip})`, now]);
        await pool.query('DELETE FROM active_tokens WHERE token = $1', [token]);
        return res.send(`<!DOCTYPE html><html><head><title>IP KHÔNG HỢP LỆ</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}</style></head><body><div class=container><h2>🌐 IP KHÔNG HỢP LỆ</h2><p>Bạn phải dùng cùng IP khi tạo link và xác minh!</p></div></body></html>`);
    }

    // Chống 1 IP dùng nhiều user trong ngày
    const today = getVietnamDate();
    const ipUsage = await pool.query('SELECT user_id FROM ip_usage WHERE ip = $1 AND date = $2', [userIP, today]);
    if (ipUsage.rows.length && ipUsage.rows[0].user_id !== userId) {
        await pool.query('INSERT INTO ip_blacklist (ip, fingerprint, reason, time) VALUES ($1, $2, $3, $4)', [userIP, fingerprint, `IP đã dùng cho user ${ipUsage.rows[0].user_id} khác`, now]);
        await pool.query('DELETE FROM active_tokens WHERE token = $1', [token]);
        return res.send(`<!DOCTYPE html><html><head><title>TRÙNG IP</title><style>body{font-family:Arial;background:linear-gradient(135deg,#ff4757,#c0392b);display:flex;justify-content:center;align-items:center;min-height:100vh;}.container{background:#fff;padding:40px;border-radius:20px;text-align:center;}h2{color:#c0392b;}.warning{background:#ffeaa7;padding:15px;border-radius:12px;margin:20px0;}</style></head><body><div class=container><h2>🚫 IP ĐÃ ĐƯỢC SỬ DỤNG</h2><div class=warning>IP ${userIP} đã được sử dụng bởi tài khoản khác trong ngày hôm nay!<br>Mỗi IP chỉ được dùng cho 1 tài khoản duy nhất.</div><p>⏰ ${now}</p><a href="https://t.me/Vuotlinkcaytienbot">🤖 Quay lại Bot</a></div></body></html>`);
    }
    if (ipUsage.rows.length === 0) {
        await pool.query('INSERT INTO ip_usage (ip, user_id, date) VALUES ($1, $2, $3)', [userIP, userId, today]);
    }

    // Ghi log IP
    await pool.query('INSERT INTO ip_logs (ip, user_id, user_agent, task_type, time) VALUES ($1, $2, $3, $4, $5)', [userIP, userId, userAgent, taskType, now]);

    console.log(`[${now}] ✅ SUCCESS User ${userId} Task ${taskType} +${getRewardByTaskType(taskType)}Đ IP ${userIP}`);

    // KHÔNG XÓA TOKEN – giữ lại cho bot check (tự xóa sau 24h)
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>🎉 XÁC MINH THÀNH CÔNG!</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#667eea,#764ba2);display:flex;justify-content:center;align-items:center;min-height:100vh;padding:15px;font-family:'Segoe UI',Arial,sans-serif}.container{background:#fff;padding:30px;border-radius:20px;text-align:center;max-width:500px;width:100%}h2{color:#2ed573;font-size:28px;margin-bottom:15px}.reward-box{background:linear-gradient(135deg,#667eea,#764ba2);padding:20px;border-radius:15px;margin:20px 0}.reward-box span{color:#ffd700;font-size:36px;font-weight:bold}.key-box{background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;word-break:break-all;font-family:monospace;font-size:14px}.copy-btn{background:#2ed573;color:#fff;border:none;padding:12px24px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:bold}.copy-btn:hover{background:#26af5f}.warning-box{font-size:11px;color:#888;margin-top:20px;padding:10px;background:#f8f9fa;border-radius:10px}</style></head><body><div class=container><h2>🎉 VƯỢT LINK THÀNH CÔNG!</h2><p>Chúc mừng bạn đã hoàn thành nhiệm vụ <strong>${taskType}</strong></p><div class=reward-box><span>+${getRewardByTaskType(taskType)} ₫</span></div><div><strong>🔑 MÃ XÁC MINH CỦA BẠN:</strong></div><div class=key-box id="keyText">${tokenValue}</div><button class="copy-btn" onclick="copyKey()">📋 COPY MÃ</button><div class=warning-box>⚠️ Mỗi IP chỉ được sử dụng cho 1 tài khoản duy nhất!<br>📌 Sau khi copy mã, quay lại Bot và dán mã để nhận thưởng!</div></div><script>function copyKey(){const text=document.getElementById("keyText").innerText;navigator.clipboard.writeText(text).then(()=>alert("✅ Đã sao chép mã! Quay lại Bot để nhận thưởng!"));}</script></body></html>`);
});

app.post('/api/delete-token', async (req, res) => {
    const { token } = req.body;
    if (token) {
        await pool.query('DELETE FROM active_tokens WHERE token = $1', [token]);
        res.json({ status: "deleted" });
    } else {
        res.status(400).json({ error: "Thiếu token" });
    }
});

app.get('/health', async (req, res) => {
    const result = await pool.query('SELECT COUNT(*) FROM active_tokens');
    res.json({ status: 'OK', vietnamTime: getVietnamDateTime(), activeTokens: parseInt(result.rows[0].count) });
});

app.listen(PORT, () => console.log(`🚀 Web Server chạy tại cổng ${PORT} | Giờ VN: ${getVietnamDateTime()}`));
