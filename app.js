var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcryptjs");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "project-login-2024";

const multer = require("multer");
const { google } = require("googleapis");
const { Readable } = require("stream");

app.use(cors());
app.use(bodyParser.json());

const mysql = require("mysql2");
require("dotenv").config();

// ✅ ใช้ pool + promise
const pool = mysql.createPool(process.env.DATABASE_URL);
const connection = pool.promise();

pool.on("error", (err) => {
  console.error("MySQL Pool Error:", err);
});

// ================== Google Drive ==================
const storage = multer.memoryStorage();
const upload = multer({ storage });

const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

oAuth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
const drive = google.drive({ version: "v3", auth: oAuth2Client });

function bufferToStream(buffer) {
  const stream = new Readable();
  stream.push(buffer);
  stream.push(null);
  return stream;
}

// ================== Routes ==================

// Register
app.post("/register", upload.single("profileImage"), async (req, res) => {
  const { tec_id, tec_name, email, password, role, position } = req.body;
  if (!tec_id || !tec_name || !email || !password || !role || !position) {
    return res.status(400).json({ status: "error", message: "Incomplete data" });
  }
  try {
    let t_profile = null;
    if (req.file) {
      const fileMetadata = {
        name: req.file.originalname,
        parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
      };
      const media = {
        mimeType: req.file.mimetype,
        body: bufferToStream(req.file.buffer),
      };
      const file = await drive.files.create({
        resource: fileMetadata,
        media,
        fields: "id",
      });
      const fileId = file.data.id;
      await drive.permissions.create({
        fileId,
        requestBody: { role: "reader", type: "anyone" },
      });
      t_profile = fileId;
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await connection.execute(
      "INSERT INTO users (tec_id, tec_name, email, password, role, position, t_profile) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [tec_id, tec_name, email, hashedPassword, role, position, t_profile]
    );
    res.json({ status: "ok", message: "Registration successful" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Image from Google Drive
app.get("/image/:id", async (req, res) => {
  try {
    const driveRes = await drive.files.get(
      { fileId: req.params.id, alt: "media" },
      { responseType: "stream" }
    );
    res.setHeader("Content-Type", "image/jpeg");
    driveRes.data.pipe(res);
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Login
app.post("/login", jsonParser, async (req, res) => {
  try {
    const [users] = await connection.execute("SELECT * FROM users WHERE email = ?", [
      req.body.email,
    ]);
    if (users.length === 0) return res.json({ status: "error", message: "No user found" });

    const isLogin = await bcrypt.compare(req.body.password, users[0].password);
    if (!isLogin) return res.json({ status: "error", message: "Login failed" });

    const token = jwt.sign({ email: users[0].email }, secret, { expiresIn: "1h" });
    res.json({
      status: "ok",
      message: "Login success",
      token,
      role: users[0].role,
      position: users[0].position,
    });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Auth
app.post("/authen", jsonParser, async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, secret);
    const [results] = await connection.execute(
      "SELECT tec_id, tec_name, role, position, t_profile FROM users WHERE email = ?",
      [decoded.email]
    );
    if (results.length === 0) return res.json({ status: "error", message: "Authentication failed" });
    res.json({ status: "ok", user: results[0] });
  } catch (err) {
    res.json({ status: "error", message: "Invalid token" });
  }
});

// Checkin
app.post("/checkin", jsonParser, async (req, res) => {
  const { tec_id, tec_name, location_in } = req.body;
  try {
    // 1. เช็คว่าเคยลงเวลาเข้าไปแล้วในวันเดียวกันหรือยัง
    const [sameDayRows] = await connection.execute(
      "SELECT * FROM attendance WHERE tec_id = ? AND DATE(Datetime_IN) = CURDATE()",
      [tec_id]
    );
    if (sameDayRows.length > 0) {
      return res.json({
        status: "error",
        message: "วันนี้คุณได้ลงเวลาเข้างานแล้ว (วันนึงลงเวลาได้ครั้งเดียว)"
      });
    }

    // 2. เช็คว่ามีการเข้างานค้างอยู่โดยไม่ checkout หรือเปล่า
    const [rows] = await connection.execute(
      "SELECT * FROM attendance WHERE tec_id = ? AND Datetime_IN IS NOT NULL AND Datetime_OUT IS NULL",
      [tec_id]
    );
    if (rows.length > 0) {
      return res.json({
        status: "error",
        message: "กรุณาลงเวลาออกงานของครั้งก่อนหน้าก่อน!"
      });
    }

    // 3. บันทึกเข้างาน (MySQL จะ auto increment attendance_id ให้เอง)
    await connection.execute(
      "INSERT INTO attendance (tec_id, tec_name, Datetime_IN, Location_IN) VALUES (?, ?, NOW(), ?)",
      [tec_id, tec_name, location_in]
    );

    res.json({ status: "ok", message: "ลงเวลาเข้างานสำเร็จ!" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Checkout
app.put("/checkout", jsonParser, async (req, res) => {
  const { tec_id, location_out } = req.body;
  if (!tec_id || !location_out) {
    return res.status(400).json({ status: "error", message: "ข้อมูลไม่ครบถ้วน" });
  }
  try {
    // 1. ต้องมีการเข้างานที่ยังไม่ checkout ถึงจะทำได้
    const [rows] = await connection.execute(
      "SELECT * FROM attendance WHERE tec_id = ? AND Datetime_OUT IS NULL",
      [tec_id]
    );
    if (rows.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "ยังไม่ได้ลงเวลาเข้างาน!"
      });
    }

    // 2. อัพเดทเวลาออก
    await connection.execute(
      "UPDATE attendance SET Datetime_OUT = NOW(), Location_OUT = ? WHERE tec_id = ? AND Datetime_OUT IS NULL",
      [location_out, tec_id]
    );

    res.json({ status: "ok", message: "ลงเวลาออกงานสำเร็จ!" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});


// Attendance list
app.get("/attendance", async (req, res) => {
  try {
    const [rows] = await connection.execute("SELECT * FROM attendance");
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Attendance by tec_id
app.get("/attendance/:tec_id", async (req, res) => {
  try {
    const [results] = await connection.execute(
      "SELECT * FROM attendance WHERE tec_id = ?",
      [req.params.tec_id]
    );
    res.json({ status: "ok", data: results });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Users
app.get("/users", async (req, res) => {
  try {
    const [results] = await connection.execute(
      "SELECT tec_id, tec_name, email, role, position, t_profile FROM users"
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Add user
app.post("/users", jsonParser, async (req, res) => {
  try {
    await connection.execute(
      "INSERT INTO users (tec_name, email, role, t_profile, position) VALUES (?, ?, ?, ?, ?)",
      [req.body.tec_name, req.body.email, req.body.role, req.body.t_profile, req.body.position]
    );
    res.json({ status: "ok", message: "User added successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Update user
app.put("/users/:id", upload.single("profileImage"), async (req, res) => {
  const { tec_name, email, role, position, password } = req.body;
  try {
    const [results] = await connection.execute(
      "SELECT t_profile FROM users WHERE tec_id = ?",
      [req.params.id]
    );
    let currentProfile = results[0]?.t_profile || null;
    let newProfile = currentProfile;

    if (req.file) {
      const media = { mimeType: req.file.mimetype, body: bufferToStream(req.file.buffer) };
      if (currentProfile) {
        await drive.files.update({ fileId: currentProfile, media });
      } else {
        const fileMetadata = {
          name: req.file.originalname,
          parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
        };
        const file = await drive.files.create({
          resource: fileMetadata,
          media,
          fields: "id",
        });
        const fileId = file.data.id;
        await drive.permissions.create({
          fileId,
          requestBody: { role: "reader", type: "anyone" },
        });
        newProfile = fileId;
      }
    }

    let query =
      "UPDATE users SET tec_name = ?, email = ?, role = ?, position = ?, t_profile = ? WHERE tec_id = ?";
    let values = [tec_name, email, role, position, newProfile, req.params.id];

    if (password) {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      query =
        "UPDATE users SET tec_name = ?, email = ?, role = ?, position = ?, t_profile = ?, password = ? WHERE tec_id = ?";
      values = [tec_name, email, role, position, newProfile, hashedPassword, req.params.id];
    }

    await connection.execute(query, values);
    res.json({ status: "ok", message: "User updated successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Delete user
app.delete("/users/:id", async (req, res) => {
  try {
    const [results] = await connection.execute(
      "SELECT t_profile FROM users WHERE tec_id = ?",
      [req.params.id]
    );
    const fileId = results[0]?.t_profile;
    if (fileId) {
      try {
        await drive.files.delete({ fileId });
      } catch (err) {
        console.error("Failed to delete file from Google Drive:", err.message);
      }
    }
    await connection.execute("DELETE FROM users WHERE tec_id = ?", [req.params.id]);
    res.json({ status: "ok", message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Get user
app.get("/user/:tec_id", async (req, res) => {
  try {
    const [results] = await connection.execute(
      "SELECT tec_id, tec_name, position FROM users WHERE tec_id = ?",
      [req.params.tec_id]
    );
    if (results.length === 0) return res.status(404).json({ status: "error", message: "User not found" });
    res.json({ status: "ok", data: results[0] });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Add Leave Record
app.post("/leave", jsonParser, async (req, res) => {
  const {
    tec_id,
    leave_type,
    written_at,
    absence_date,
    phone,
    leave_status,
    approval_status,
    last_leave_date,
    position,
  } = req.body;
  if (!leave_type || !written_at || !absence_date || !phone || !leave_status || !position) {
    return res.status(400).json({ status: "error", message: "ข้อมูลไม่ครบถ้วน" });
  }
  try {
    await connection.execute(
      `INSERT INTO leaverecords 
      (tec_id, leave_type, written_at, absence_date, phone, leave_status, approval_status, last_leave_date, position) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [tec_id, leave_type, written_at, absence_date, phone, leave_status, approval_status, last_leave_date || null, position]
    );
    res.json({ status: "ok", message: "บันทึกข้อมูลการลาสำเร็จ" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Get Leave by tec_id
app.get("/leave/:tec_id", async (req, res) => {
  try {
    const [rows] = await connection.execute(
      `SELECT lr.*, u.tec_name, u.role, u.position 
       FROM leaverecords lr 
       INNER JOIN users u ON lr.tec_id = u.tec_id 
       WHERE lr.tec_id = ?`,
      [req.params.tec_id]
    );
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Update Leave
app.put("/leave/:leave_id", jsonParser, async (req, res) => {
  const {
    leave_type,
    written_at,
    role,
    position,
    absence_date,
    last_leave_date,
    phone,
    leave_status,
    approval_status,
  } = req.body;
  try {
    await connection.execute(
      `UPDATE leaverecords 
       SET leave_type = ?, written_at = ?, role = ?, position = ?, absence_date = ?, last_leave_date = ?, 
           phone = ?, leave_status = ?, approval_status = ? 
       WHERE leave_id = ?`,
      [
        leave_type,
        written_at,
        role,
        position,
        absence_date,
        last_leave_date,
        phone,
        leave_status,
        approval_status,
        req.params.leave_id,
      ]
    );
    res.json({ status: "ok", message: "Leave record updated successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Delete Leave
app.delete("/leave/:leave_id", async (req, res) => {
  try {
    await connection.execute("DELETE FROM leaverecords WHERE leave_id = ?", [req.params.leave_id]);
    res.json({ status: "ok", message: "Leave record deleted successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Get all Leave records
app.get("/leaverecords", async (req, res) => {
  try {
    const [rows] = await connection.execute("SELECT * FROM leaverecords");
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Get leave records by tec_id
app.get("/leaverecords/:tec_id", async (req, res) => {
  try {
    const [rows] = await connection.execute(
      `SELECT leaverecords.*, users.tec_name, users.position 
       FROM leaverecords 
       JOIN users ON leaverecords.tec_id = users.tec_id
       WHERE leaverecords.tec_id = ?`,
      [req.params.tec_id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ status: "error", message: "No leave records found" });
    }
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Get last absence_date
app.get("/last_leave/:tec_id", async (req, res) => {
  try {
    const [results] = await connection.execute(
      "SELECT absence_date FROM leaverecords WHERE tec_id = ? ORDER BY leave_id DESC LIMIT 1",
      [req.params.tec_id]
    );
    if (results.length === 0) {
      return res.json({ status: "ok", last_leave_date: "ไม่มีข้อมูล" });
    }
    res.json({ status: "ok", last_leave_date: results[0].absence_date });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Update Approval
app.post("/updateApproval", async (req, res) => {
  try {
    const { leave_id, approval_status } = req.body;
    await connection.execute(
      "UPDATE leaverecords SET approval_status = ? WHERE leave_id = ?",
      [approval_status, leave_id]
    );
    res.json({ status: "ok", message: "Approval status updated successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ================== Start Server ==================
app.listen(process.env.PORT || 3333, function () {
  console.log("CORS-enabled web server listening on port 3333");
});
