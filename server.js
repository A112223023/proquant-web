const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const rateLimit = require('express-rate-limit'); // 1. 引入防護套件

const app = express();
const db = new sqlite3.Database('./users.db');

app.use(bodyParser.json());
// 讓伺服器去 public 資料夾找 HTML 檔案
app.use(express.static('public'));

// 2. 防護設定：同一個 IP 在 1 小時內最多只能註冊 3 個帳號
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 60 分鐘
    max: 3, 
    message: { error: '您的註冊次數太頻繁了，請一小時後再試！' },
    standardHeaders: true,
    legacyHeaders: false,
});

// 初始化資料庫
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
});

// 註冊 API (套用 registerLimiter 防護)
app.post('/api/register', registerLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: "此帳號已被註冊" });
            res.json({ message: "註冊成功！" });
        });
    } catch (e) {
        res.status(500).json({ error: "伺服器錯誤" });
    }
});

// 登入 API
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "帳號不存在" });
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            res.json({ message: "登入成功！" });
        } else {
            res.status(400).json({ error: "密碼錯誤" });
        }
    });
});

// 3. 重要：讓雲端平台決定 Port，如果沒有就用 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`伺服器運行中：http://localhost:${PORT}`);
});