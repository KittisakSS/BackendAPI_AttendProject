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
const path = require("path");

const { google } = require("googleapis");
const fs = require("fs");
const { Readable } = require("stream");

app.use(cors());
app.use(bodyParser.json());

const mysql = require("mysql2");
require('dotenv').config()

// Create the connection to database
const connection = mysql.createConnection(process.env.DATABASE_URL);

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, "uploads/");
//   },
//   filename: (req, file, cb) => {
//     cb(null, Date.now() + path.extname(file.originalname));
//   },
// });
// const upload = multer({ storage });

// // Serve uploaded files
// app.use("/uploads", express.static("uploads"));

// // User Registration with profile image upload
// app.post("/register", upload.single("profileImage"), (req, res) => {
//   const { tec_id, tec_name, email, password, role, position } = req.body;
//   const t_profile = req.file ? req.file.filename : null;

//   if (!tec_id || !tec_name || !email || !password || !role || !position) {
//     return res.status(400).json({ status: "error", message: "Incomplete data" });
//   }

//   bcrypt.hash(password, saltRounds, (err, hash) => {
//     if (err) return res.status(500).json({ status: "error", message: err.message });

//     connection.execute(
//       "INSERT INTO users (tec_id, tec_name, email, password, role, position, t_profile) VALUES (?, ?, ?, ?, ?, ?, ?)",
//       [tec_id, tec_name, email, hash, role, position, t_profile],
//       (err) => {
//         if (err) return res.status(500).json({ status: "error", message: err.message });

//         res.json({
//           status: "ok",
//           message: "Registration successful",
//           data: { tec_id, tec_name, email, role, position, t_profile },
//         });
//       }
//     );
//   });
// });

// ตั้งค่า multer แบบ Memory Storage
const storage = multer.memoryStorage();
const upload = multer({ storage });

// 📌 OAuth2 (ใช้ quota ของ user)
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI // ไม่ใช้จริงใน backend แต่ต้องใส่ให้ครบ
);

// ใช้ credentials จาก .env แทน keyFile
oAuth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
const drive = google.drive({ version: "v3", auth: oAuth2Client });

function bufferToStream(buffer) {
  const stream = new Readable();
  stream.push(buffer);
  stream.push(null);
  return stream;
}


app.post("/register", upload.single("profileImage"), async (req, res) => {
  const { tec_id, tec_name, email, password, role, position } = req.body;

  if (!tec_id || !tec_name || !email || !password || !role || !position) {
    return res.status(400).json({ status: "error", message: "Incomplete data" });
  }

  try {
    let t_profile = null;

    if (req.file) {
      // 📤 Upload ไป Google Drive ของคุณ
      const fileMetadata = {
        name: req.file.originalname,
        parents: [process.env.GOOGLE_DRIVE_FOLDER_ID], // ใส่ Folder ID ที่คุณมีสิทธิ์
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

      // 🔓 ทำให้ดูได้ทุกคน
      await drive.permissions.create({
        fileId,
        requestBody: { role: "reader", type: "anyone" },
      });

      t_profile = `https://drive.google.com/uc?export=view&id=${fileId}`;
    }

    // 🗄 บันทึกลง DB
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    connection.execute(
      "INSERT INTO users (tec_id, tec_name, email, password, role, position, t_profile) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [tec_id, tec_name, email, hashedPassword, role, position, t_profile],
      (err) => {
        if (err)
          return res.status(500).json({ status: "error", message: err.message });

        res.json({
          status: "ok",
          message: "Registration successful",
          data: { tec_id, tec_name, email, role, position, t_profile },
        });
      }
    );
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/login", jsonParser, (req, res) => {
  connection.execute(
    "SELECT * FROM users WHERE email = ?",
    [req.body.email],
    (err, users) => {
      if (err) return res.json({ status: "error", message: err });
      if (users.length === 0) return res.json({ status: "error", message: "No user found" });

      bcrypt.compare(req.body.password, users[0].password, (err, isLogin) => {
        if (err) return res.json({ status: "error", message: err });
        if (isLogin) {
          const token = jwt.sign({ email: users[0].email }, secret, { expiresIn: "1h" });
          res.json({
            status: "ok",
            message: "Login success",
            token,
            role: users[0].role,
            position: users[0].position, // Include position in the response
          });
        } else {
          res.json({ status: "error", message: "Login failed" });
        }
      });
    }
  );
});


app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);

    connection.execute(
      "SELECT tec_id, tec_name, role, position, t_profile FROM users WHERE email = ?",
      [decoded.email],
      function (err, results) {
        if (err || results.length === 0) {
          res.json({ status: "error", message: "Authentication failed" });
          return;
        }
        res.json({
          status: "ok",
          user: {
            tec_id: results[0].tec_id,
            tec_name: results[0].tec_name,
            role: results[0].role,
            position: results[0].position, // เพิ่มข้อมูลตำแหน่งใน response
            t_profile: results[0].t_profile,
          },
        });
      }
    );
  } catch (err) {
    res.json({ status: "error", message: "Invalid token" });
  }
});

app.post("/checkin", jsonParser, function (req, res) {
  const { tec_id, tec_name, location_in } = req.body;

  connection.execute(
    "SELECT * FROM attendance WHERE tec_id = ? AND Datetime_IN IS NOT NULL AND Datetime_OUT IS NULL",
    [tec_id],
    function (err, rows) {
      if (err) {
        res.json({ status: "error", message: err.message });
        return;
      }
      if (rows.length > 0) {
        res.json({ status: "error", message: "กรุณาลงเวลาออกงานของครั้งก่อนหน้าก่อน!" });
        return;
      }

      connection.execute(
        "INSERT INTO attendance (tec_id, tec_name, Datetime_IN, Location_IN) VALUES (?, ?, NOW(), ?)",
        [tec_id, tec_name, location_in],
        function (err) {
          if (err) {
            res.json({ status: "error", message: err.message });
            return;
          }
          res.json({ status: "ok", message: "ลงเวลาเข้างานสำเร็จ!" });
        }
      );
    }
  );
});


app.put("/checkout", jsonParser, function (req, res) {
  const { tec_id, location_out } = req.body;

  if (!tec_id || !location_out) {
    return res.status(400).json({ status: "error", message: "ข้อมูลไม่ครบถ้วน" });
  }

  connection.execute(
    "SELECT * FROM attendance WHERE tec_id = ? AND Datetime_OUT IS NULL",
    [tec_id],
    function (err, rows) {
      if (err) {
        console.error("Database Error:", err.message);
        return res.status(500).json({ status: "error", message: err.message });
      }

      if (rows.length === 0) {
        return res.status(400).json({ status: "error", message: "ยังไม่ได้ลงเวลาเข้างาน!" });
      }

      connection.execute(
        "UPDATE attendance SET Datetime_OUT = NOW(), Location_OUT = ? WHERE tec_id = ? AND Datetime_OUT IS NULL",
        [location_out, tec_id],
        function (err) {
          if (err) {
            console.error("Error updating record:", err.message);
            return res.status(500).json({ status: "error", message: err.message });
          }
          res.json({ status: "ok", message: "ลงเวลาออกงานสำเร็จ!" });
        }
      );
    }
  );
});


app.get("/attendance", function (req, res) {
  connection.execute(
    "SELECT * FROM attendance",
    function (err, rows) {
      if (err) {
        res.json({ status: "error", message: err.message });
        return;
      }
      res.json({ status: "ok", data: rows });
    }
  );
});

app.get("/attendance/:tec_id", (req, res) => {
  const tec_id = req.params.tec_id;
  connection.execute(
    "SELECT * FROM attendance WHERE tec_id = ?",
    [tec_id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ status: "error", message: err.message });
      }
      res.json({ status: "ok", data: results });
    }
  );
});


// Read Users (Exclude Password)
app.get("/users", function (req, res) {
  connection.execute(
    "SELECT tec_id, tec_name, email, role, position, t_profile FROM users", // Add position
    function (err, results) {
      if (err) {
        res.status(500).json({ status: "error", message: err });
      } else {
        res.json(results);
      }
    }
  );
});

// Create User
app.post("/users", jsonParser, function (req, res) {
  connection.execute(
    "INSERT INTO users (tec_name, email, role, t_profile, position) VALUES (?, ?, ?, ?, ?)",
    [req.body.tec_name, req.body.email, req.body.role, req.body.t_profile, req.body.position],
    function (err) {
      if (err) res.status(500).json({ status: "error", message: err });
      else res.json({ status: "ok", message: "User added successfully" });
    }
  );
});

// Update User
app.put("/users/:id", upload.single("profileImage"), async (req, res) => {
  const { tec_name, email, role, position, password } = req.body;
  const t_profile = req.file ? req.file.filename : null; // รับชื่อไฟล์จาก multer

  try {
    // ดึงข้อมูล t_profile เดิมจากฐานข้อมูลถ้าไม่มีการอัปโหลดรูปใหม่
    const [results] = await connection.promise().execute(
      "SELECT t_profile FROM users WHERE tec_id = ?",
      [req.params.id]
    );

    const currentProfile = results[0]?.t_profile || null;
    const newProfile = t_profile || currentProfile; // ใช้รูปใหม่ถ้ามี หรือใช้รูปเดิมถ้าไม่มีการอัปโหลดใหม่

    // ตรวจสอบว่ามีการส่งรหัสผ่านใหม่หรือไม่
    let updateQuery = "UPDATE users SET tec_name = ?, email = ?, role = ?, position = ?, t_profile = ? WHERE tec_id = ?";
    let updateValues = [tec_name, email, role, position, newProfile, req.params.id];

    if (password) {
      // แฮชรหัสผ่านใหม่
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      updateQuery = "UPDATE users SET tec_name = ?, email = ?, role = ?, position = ?, t_profile = ?, password = ? WHERE tec_id = ?";
      updateValues = [tec_name, email, role, position, newProfile, hashedPassword, req.params.id];
    }

    // อัปเดตข้อมูลผู้ใช้ในฐานข้อมูล
    await connection.promise().execute(updateQuery, updateValues);

    res.json({ status: "ok", message: "User updated successfully" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});




// Delete User
app.delete("/users/:id", function (req, res) {
  connection.execute(
    "DELETE FROM users WHERE tec_id = ?",
    [req.params.id],
    function (err) {
      if (err) res.status(500).json({ status: "error", message: err });
      else res.json({ status: "ok", message: "User deleted successfully" });
    }
  );
});

app.get("/user/:tec_id", (req, res) => {
  const tec_id = req.params.tec_id;

  connection.execute(
    "SELECT tec_id, tec_name, position FROM users WHERE tec_id = ?",
    [tec_id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ status: "error", message: err.message });
      }
      if (results.length === 0) {
        return res.status(404).json({ status: "error", message: "User not found" });
      }
      res.json({ status: "ok", data: results[0] });
    }
  );
});



// Add Leave Record
app.post("/leave", jsonParser, (req, res) => {
  const {
    tec_id,
    leave_type,
    written_at,
    absence_date,
    phone,
    leave_status,
    approval_status,
    last_leave_date,
    position, // เพิ่ม field position
  } = req.body;

  // ตรวจสอบว่าข้อมูลที่จำเป็นครบถ้วน
  if (!leave_type || !written_at || !absence_date || !phone || !leave_status || !position) {
    return res.status(400).json({ status: "error", message: "ข้อมูลไม่ครบถ้วน" });
  }

  // แทรกข้อมูลลงในตาราง leaverecords
  connection.execute(
    `INSERT INTO leaverecords 
    (tec_id, leave_type, written_at, absence_date, phone, leave_status, approval_status, last_leave_date, position) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      tec_id,
      leave_type,
      written_at,
      absence_date,
      phone,
      leave_status,
      approval_status,
      last_leave_date || null, // ถ้าไม่มีค่า ให้ใช้ null
      position, // บันทึก position ลงฐานข้อมูล
    ],
    (err) => {
      if (err) {
        return res.status(500).json({ status: "error", message: err.message });
      }
      res.json({ status: "ok", message: "บันทึกข้อมูลการลาสำเร็จ" });
    }
  );
});




// Get Leave Records by tec_id
app.get("/leave/:tec_id", function (req, res) {
  const tec_id = req.params.tec_id;

  connection.execute(
    `SELECT lr.*, u.tec_name, u.role, u.position 
     FROM leaverecords lr 
     INNER JOIN users u ON lr.tec_id = u.tec_id 
     WHERE lr.tec_id = ?`,
    [tec_id],
    function (err, rows) {
      if (err) {
        res.status(500).json({ status: "error", message: err.message });
      } else {
        res.json({ status: "ok", data: rows });
      }
    }
  );
});

// Update Leave Record
app.put("/leave/:leave_id", jsonParser, function (req, res) {
  const leave_id = req.params.leave_id;
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

  connection.execute(
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
      leave_id,
    ],
    function (err) {
      if (err) res.status(500).json({ status: "error", message: err });
      else res.json({ status: "ok", message: "Leave record updated successfully" });
    }
  );
});

// Delete Leave Record
app.delete("/leave/:leave_id", function (req, res) {
  const leave_id = req.params.leave_id;

  connection.execute(
    "DELETE FROM leaverecords WHERE leave_id = ?",
    [leave_id],
    function (err) {
      if (err) {
        res.status(500).json({ status: "error", message: err.message });
      } else {
        res.json({ status: "ok", message: "Leave record deleted successfully" });
      }
    }
  );
});

// API to fetch Leave Records
app.get("/leaverecords", (req, res) => {
  connection.execute(
    "SELECT * FROM leaverecords",
    (err, rows) => {
      if (err) {
        res.status(500).json({ status: "error", message: err.message });
        return;
      }
      res.json({ status: "ok", data: rows });
    }
  );
});

app.get("/leaverecords/:tec_id", (req, res) => {
  const { tec_id } = req.params;

  if (!tec_id) {
    return res.status(400).json({ status: "error", message: "Missing tec_id" });
  }

  // ใช้ JOIN เพื่อดึง tec_name และ position จากตาราง users
  const query = `
    SELECT leaverecords.*, users.tec_name, users.position 
    FROM leaverecords 
    JOIN users ON leaverecords.tec_id = users.tec_id
    WHERE leaverecords.tec_id = ?
  `;

  connection.execute(query, [tec_id], (err, rows) => {
    if (err) {
      return res.status(500).json({ status: "error", message: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ status: "error", message: "No leave records found" });
    }

    res.json({ status: "ok", data: rows });
  });
});



// Get last absence_date for a specific user
app.get("/last_leave/:tec_id", (req, res) => {
  const tec_id = req.params.tec_id;

  connection.execute(
    "SELECT absence_date FROM leaverecords WHERE tec_id = ? ORDER BY leave_id DESC LIMIT 1",
    [tec_id],
    (err, results) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ status: "error", message: err.message });
      }

      // console.log("Results:", results);

      if (results.length === 0) {
        return res.json({ status: "ok", last_leave_date: "ไม่มีข้อมูล" });
      }

      res.json({ status: "ok", last_leave_date: results[0].absence_date });
    }
  );
});

app.post("/updateApproval", (req, res) => {
  const { leave_id, approval_status } = req.body;
  connection.execute(
    "UPDATE leaverecords SET approval_status = ? WHERE leave_id = ?",
    [approval_status, leave_id],
    (err, results) => {
      if (err) {
        res.status(500).json({ status: "error", message: err.message });
        return;
      }
      res.json({ status: "ok", message: "Approval status updated successfully" });
    }
  );
});


app.listen(process.env.PORT || 3333, function () {
  console.log("CORS-enabled web server listening on port 3333");
});
