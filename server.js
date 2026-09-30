require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const isProduction = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT || 1000);

// -------------------------------------------------
// SECURITY / SERVER SETTINGS
// -------------------------------------------------

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error(
        "JWT_SECRET must be configured and at least 32 characters long."
    );
}

// Support both localhost and 127.0.0.1 automatically.
// You can also override this from .env.
const allowedOrigins = (
    process.env.FRONTEND_URL ||
    "http://localhost:1000,http://127.0.0.1:1000"
)
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        },
        contentSecurityPolicy: false
    })
);

app.use(
    cors({
        origin(origin, callback) {
            // Same-origin requests and tools such as Postman
            // may not send an Origin header.
            if (!origin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(new Error("CORS origin not allowed"));
        },
        methods: ["GET", "POST", "PUT", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        maxAge: 86400
    })
);

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "200kb" }));

// -------------------------------------------------
// RATE LIMITERS
// -------------------------------------------------

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        message: "Too many requests. Please try again later."
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        message: "Too many login attempts. Please try again later."
    }
});

const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        message: "Registration limit reached. Please try again later."
    }
});

app.use("/api", apiLimiter);

// -------------------------------------------------
// STATIC FRONTEND
// -------------------------------------------------

const publicDir = path.join(__dirname, "../public");

app.use(
    express.static(publicDir, {
        index: "index.html"
    })
);

// -------------------------------------------------
// FILE UPLOADS
// -------------------------------------------------

const uploadDir = path.join(__dirname, "..", "uploads");

fs.mkdirSync(uploadDir, {
    recursive: true
});

const allowedMimeTypes = new Set([
    "image/jpeg",
    "image/png",
    "image/webp"
]);

const allowedExtensions = new Set([
    ".jpg",
    ".jpeg",
    ".png",
    ".webp"
]);

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, uploadDir);
    },

    filename: (_req, file, cb) => {
        const ext = path
            .extname(file.originalname || "")
            .toLowerCase();

        cb(
            null,
            `${Date.now()}-${crypto
                .randomBytes(12)
                .toString("hex")}${ext}`
        );
    }
});

const upload = multer({
    storage,

    limits: {
        fileSize: 5 * 1024 * 1024,
        files: 1,
        fields: 12
    },

    fileFilter: (_req, file, cb) => {
        const ext = path
            .extname(file.originalname || "")
            .toLowerCase();

        if (
            allowedMimeTypes.has(file.mimetype) &&
            allowedExtensions.has(ext)
        ) {
            return cb(null, true);
        }

        return cb(
            new Error(
                "Only JPG, PNG and WEBP images are allowed."
            )
        );
    }
});

// Student ID card photos are intentionally public.
// Only approved student information is exposed through
// the public profile API.
app.use(
    "/uploads",
    express.static(uploadDir, {
        maxAge: "7d",
        immutable: true
    })
);

// -------------------------------------------------
// POSTGRESQL
// -------------------------------------------------

const poolConfig = process.env.DATABASE_URL
    ? {
          connectionString: process.env.DATABASE_URL,
          max: 10,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 10000,
          ssl: isProduction
              ? { rejectUnauthorized: false }
              : false
      }
    : {
          host: process.env.DB_HOST || "127.0.0.1",
          port: Number(process.env.DB_PORT || 5432),
          user: process.env.DB_USER || "postgres",
          password: process.env.DB_PASSWORD || "",
          database: process.env.DB_NAME || "vericampus",
          max: 10,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 10000,
          ssl: false
      };

const db = new Pool(poolConfig);

db.on("error", err => {
    console.error(
        "Unexpected PostgreSQL pool error:",
        err.message
    );
});

async function testDatabaseConnection() {
    const client = await db.connect();

    try {
        await client.query("SELECT 1");

        console.log(
            "PostgreSQL connected successfully."
        );
    } finally {
        client.release();
    }
}

// -------------------------------------------------
// EMAIL
// -------------------------------------------------

const mailer = nodemailer.createTransport({
    service: "gmail",

    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_APP_PASSWORD
    }
});

const sender = process.env.MAIL_USER || "";
const admin = process.env.ADMIN_EMAIL || "";

async function testEmailConnection() {
    if (
        !sender ||
        !process.env.MAIL_APP_PASSWORD
    ) {
        console.warn(
            "Gmail is not configured. Email features will fail until configured."
        );

        return false;
    }

    try {
        await mailer.verify();

        console.log(
            "Gmail SMTP connected successfully."
        );

        return true;
    } catch (error) {
        console.warn(
            "Gmail SMTP verification failed:",
            error.message
        );

        return false;
    }
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function mail(to, subject, html) {
    if (
        !sender ||
        !process.env.MAIL_APP_PASSWORD
    ) {
        throw new Error(
            "Gmail is not configured"
        );
    }

    return mailer.sendMail({
        from: `"VeriCampus" <${sender}>`,
        to,
        subject,

        html: `
            <div
                style="
                    font-family:Arial;
                    max-width:600px;
                    margin:auto;
                    padding:25px
                "
            >
                <h2>🎓 VeriCampus</h2>

                ${html}

                <hr>

                <small>
                    Vivek College of Commerce (Autonomous)
                </small>
            </div>
        `
    });
}

// -------------------------------------------------
// VALIDATION HELPERS
// -------------------------------------------------

const EMAIL_RE =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const PHONE_RE =
    /^(?:\+91[- ]?)?[6-9]\d{9}$/;

const STUDENT_ID_RE =
    /^\d{10}$/;

function cleanText(value, max = 100) {
    return String(value ?? "")
        .trim()
        .replace(/\s+/g, " ")
        .slice(0, max);
}

function cleanEmail(value) {
    return cleanText(value, 190)
        .toLowerCase();
}

function validateStudentFields({
    name,
    email,
    phone,
    course,
    division,
    year_name
}) {
    const n = cleanText(name, 100);
    const e = cleanEmail(email);

    const p = cleanText(phone, 20)
        .replace(/[()]/g, "");

    const c = cleanText(course, 100);

    const d = division
        ? cleanText(division, 20)
        : null;

    const y = year_name
        ? cleanText(year_name, 30)
        : null;

    if (!n || n.length < 2) {
        throw new Error(
            "Valid student name is required"
        );
    }

    if (!EMAIL_RE.test(e)) {
        throw new Error(
            "Valid email address is required"
        );
    }

    if (!PHONE_RE.test(p)) {
        throw new Error(
            "Valid Indian mobile number is required"
        );
    }

    if (!c) {
        throw new Error(
            "Course is required"
        );
    }

    return {
        name: n,
        email: e,
        phone: p,
        course: c,
        division: d,
        year_name: y
    };
}

function validateTeacherFields({
    name,
    email
}) {
    const n = cleanText(name, 100);
    const e = cleanEmail(email);

    if (!n || n.length < 2) {
        throw new Error(
            "Valid teacher name is required"
        );
    }

    if (!EMAIL_RE.test(e)) {
        throw new Error(
            "Valid email address is required"
        );
    }

    return {
        name: n,
        email: e
    };
}

function studentId() {
    return String(
        crypto.randomInt(
            1000000000,
            10000000000
        )
    );
}

function accessCode() {
    return crypto
        .randomBytes(6)
        .toString("hex")
        .toUpperCase()
        .slice(0, 8);
}

function otpCode() {
    return String(
        crypto.randomInt(
            100000,
            1000000
        )
    );
}

function getBearerToken(req) {
    const header = String(
        req.headers.authorization || ""
    );

    if (!header.startsWith("Bearer ")) {
        return "";
    }

    return header
        .slice(7)
        .trim();
}

// -------------------------------------------------
// AUTH HELPERS
// -------------------------------------------------

async function teacherAuth(
    req,
    res,
    next
) {
    try {
        const token =
            getBearerToken(req);

        if (!token) {
            return res.status(401).json({
                message:
                    "Teacher login required"
            });
        }

        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (payload.role !== "teacher") {
            return res.status(403).json({
                message:
                    "Teacher access required"
            });
        }

        const { rows } =
            await db.query(
                `
                SELECT
                    id,
                    name,
                    email,
                    role,
                    status
                FROM teachers
                WHERE id=$1
                LIMIT 1
                `,
                [payload.id]
            );

        if (
            !rows.length ||
            rows[0].status !== "active"
        ) {
            return res.status(401).json({
                message:
                    "Teacher account is inactive"
            });
        }

        req.user = rows[0];

        next();
    } catch (_error) {
        return res.status(401).json({
            message:
                "Invalid or expired teacher token"
        });
    }
}

async function studentAuth(
    req,
    res,
    next
) {
    try {
        const token =
            getBearerToken(req);

        if (!token) {
            return res.status(401).json({
                message:
                    "Student login required"
            });
        }

        const payload = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (payload.role !== "student") {
            return res.status(403).json({
                message:
                    "Student access required"
            });
        }

        const { rows } =
            await db.query(
                `
                SELECT
                    id,
                    student_id,
                    name,
                    email,
                    status
                FROM students
                WHERE id=$1
                LIMIT 1
                `,
                [payload.id]
            );

        if (!rows.length) {
            return res.status(401).json({
                message:
                    "Student account not found"
            });
        }

        req.user = rows[0];

        next();
    } catch (_error) {
        return res.status(401).json({
            message:
                "Invalid or expired student token"
        });
    }
}

function signToken(
    payload,
    expiresIn
) {
    return jwt.sign(
        payload,
        process.env.JWT_SECRET,
        {
            expiresIn,
            issuer: "vericampus",
            audience:
                "vericampus-users"
        }
    );
}

// -------------------------------------------------
// TEACHER REGISTRATION
// -------------------------------------------------

app.post(
    "/api/teacher/register",
    registrationLimiter,
    async (req, res) => {
        try {
            const {
                name,
                email
            } =
                validateTeacherFields(
                    req.body
                );

            const registrationKey =
                cleanText(
                    req.body.registrationKey,
                    200
                );

            if (
                !process.env
                    .TEACHER_REGISTRATION_KEY ||
                registrationKey !==
                    process.env
                        .TEACHER_REGISTRATION_KEY
            ) {
                return res.status(403).json({
                    message:
                        "Valid teacher registration key is required."
                });
            }

            const client =
                await db.connect();

            try {
                await client.query(
                    "BEGIN"
                );

                await client.query(
                    "SELECT pg_advisory_xact_lock(72839401)"
                );

                const countResult =
                    await client.query(
                        `
                        SELECT COUNT(*)::int AS total
                        FROM teachers
                        `
                    );

                if (
                    countResult.rows[0]
                        .total >= 2
                ) {
                    await client.query(
                        "ROLLBACK"
                    );

                    return res.status(403).json({
                        message:
                            "Admin limit reached. Maximum 2 teacher/admin accounts are allowed."
                    });
                }

                const existing =
                    await client.query(
                        `
                        SELECT id
                        FROM teachers
                        WHERE email=$1
                        `,
                        [email]
                    );

                if (existing.rows.length) {
                    await client.query(
                        "ROLLBACK"
                    );

                    return res.status(409).json({
                        message:
                            "Teacher email already registered"
                    });
                }

                const code =
                    accessCode();

                const hash =
                    await bcrypt.hash(
                        code,
                        12
                    );

                await client.query(
                    `
                    INSERT INTO teachers
                    (
                        name,
                        email,
                        access_code_hash,
                        role,
                        status
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        'teacher',
                        'active'
                    )
                    `,
                    [
                        name,
                        email,
                        hash
                    ]
                );

                await client.query(
                    "COMMIT"
                );

                try {
                    await mail(
                        email,
                        "Teacher Access Code — VeriCampus",
                        `
                        <p>
                            Hi
                            <b>
                                ${escapeHtml(name)}
                            </b>,
                        </p>

                        <p>
                            Your VeriCampus teacher
                            account has been created.
                        </p>

                        <p>
                            <b>Your Access Code:</b>
                            ${escapeHtml(code)}
                        </p>

                        <p>
                            Use your registered email
                            and this access code to log in.
                        </p>
                        `
                    );
                } catch (mailError) {
                    console.warn(
                        "Teacher email failed:",
                        mailError.message
                    );
                }

                return res.json({
                    message:
                        "Teacher registered successfully. Access code sent to email."
                });
            } catch (error) {
                await client.query(
                    "ROLLBACK"
                );

                throw error;
            } finally {
                client.release();
            }
        } catch (error) {
            console.error(
                "Teacher registration error:",
                error.message
            );

            return res.status(400).json({
                message:
                    error.message ||
                    "Teacher registration failed"
            });
        }
    }
);

// -------------------------------------------------
// TEACHER LOGIN
// -------------------------------------------------

app.post(
    "/api/teacher/login",
    authLimiter,
    async (req, res) => {
        try {
            const email =
                cleanEmail(
                    req.body.email
                );

            const accessCodeValue =
                cleanText(
                    req.body.accessCode,
                    20
                );

            if (
                !EMAIL_RE.test(email) ||
                !accessCodeValue
            ) {
                return res.status(400).json({
                    message:
                        "Teacher email and access code are required"
                });
            }

            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        name,
                        email,
                        access_code_hash,
                        role,
                        status
                    FROM teachers
                    WHERE email=$1
                    LIMIT 1
                    `,
                    [email]
                );

            if (
                !rows.length ||
                rows[0].status !==
                    "active"
            ) {
                return res.status(401).json({
                    message:
                        "Invalid teacher credentials"
                });
            }

            const teacher =
                rows[0];

            const valid =
                await bcrypt.compare(
                    accessCodeValue,
                    teacher.access_code_hash
                );

            if (!valid) {
                return res.status(401).json({
                    message:
                        "Invalid teacher credentials"
                });
            }

            const token =
                signToken(
                    {
                        id: teacher.id,
                        role: "teacher"
                    },
                    "2h"
                );

            return res.json({
                message:
                    "Teacher login successful",

                token,

                teacher: {
                    id: teacher.id,
                    name: teacher.name,
                    email: teacher.email,
                    role: teacher.role
                }
            });
        } catch (error) {
            console.error(
                "Teacher login error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Teacher login failed"
            });
        }
    }
);

// -------------------------------------------------
// TEACHER PROFILE
// -------------------------------------------------

app.get(
    "/api/teacher/profile",
    teacherAuth,
    async (req, res) => {
        try {
            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        name,
                        email,
                        role,
                        status,
                        created_at
                    FROM teachers
                    WHERE id=$1
                    `,
                    [req.user.id]
                );

            if (!rows.length) {
                return res.status(404).json({
                    message:
                        "Teacher profile not found"
                });
            }

            return res.json(
                rows[0]
            );
        } catch (error) {
            console.error(
                "Teacher profile error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Teacher profile load failed"
            });
        }
    }
);

app.put(
    "/api/teacher/profile",
    teacherAuth,
    async (req, res) => {
        try {
            const {
                name,
                email
            } =
                validateTeacherFields(
                    req.body
                );

            const duplicate =
                await db.query(
                    `
                    SELECT id
                    FROM teachers
                    WHERE email=$1
                    AND id<>$2
                    `,
                    [
                        email,
                        req.user.id
                    ]
                );

            if (
                duplicate.rows.length
            ) {
                return res.status(409).json({
                    message:
                        "Teacher email already registered"
                });
            }

            const result =
                await db.query(
                    `
                    UPDATE teachers
                    SET
                        name=$1,
                        email=$2
                    WHERE id=$3
                    RETURNING
                        id,
                        name,
                        email,
                        role,
                        status
                    `,
                    [
                        name,
                        email,
                        req.user.id
                    ]
                );

            return res.json({
                message:
                    "Teacher profile updated successfully",

                teacher:
                    result.rows[0]
            });
        } catch (error) {
            console.error(
                "Teacher profile update error:",
                error.message
            );

            return res.status(400).json({
                message:
                    error.message ||
                    "Teacher profile update failed"
            });
        }
    }
);

// -------------------------------------------------
// HEALTH CHECK
// -------------------------------------------------

app.get(
    "/api/health",
    async (_req, res) => {
        try {
            await db.query(
                "SELECT 1"
            );

            return res.json({
                ok: true,
                database:
                    "connected"
            });
        } catch (_error) {
            return res.status(503).json({
                ok: false,
                database:
                    "unavailable"
            });
        }
    }
);

// -------------------------------------------------
// STUDENT REGISTRATION
// -------------------------------------------------

app.post(
    "/api/student/register",
    registrationLimiter,
    upload.single("photo"),
    async (req, res) => {
        try {
            const fields =
                validateStudentFields(
                    req.body
                );

            if (!req.file) {
                return res.status(400).json({
                    message:
                        "Student photo is required"
                });
            }

            const existing =
                await db.query(
                    `
                    SELECT id
                    FROM students
                    WHERE email=$1
                    `,
                    [fields.email]
                );

            if (
                existing.rows.length
            ) {
                fs.unlink(
                    req.file.path,
                    () => {}
                );

                return res.status(409).json({
                    message:
                        "Email already registered"
                });
            }

            let sid =
                studentId();

            for (
                let i = 0;
                i < 5;
                i++
            ) {
                const check =
                    await db.query(
                        `
                        SELECT 1
                        FROM students
                        WHERE student_id=$1
                        `,
                        [sid]
                    );

                if (!check.rows.length) {
                    break;
                }

                sid =
                    studentId();
            }

            const photoPath =
                "/uploads/" +
                req.file.filename;

            /*
             * IMPORTANT:
             * We explicitly set status='pending'
             * so every new student starts pending.
             */

            const result =
                await db.query(
                    `
                    INSERT INTO students
                    (
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        'pending'
                    )
                    RETURNING
                        id,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_at
                    `,
                    [
                        sid,
                        fields.name,
                        fields.email,
                        fields.phone,
                        fields.course,
                        fields.division,
                        fields.year_name,
                        photoPath
                    ]
                );

            try {
                await mail(
                    fields.email,
                    "Registration Received — VeriCampus",
                    `
                    <p>
                        Hi
                        <b>
                            ${escapeHtml(
                                fields.name
                            )}
                        </b>,
                    </p>

                    <p>
                        Your registration at
                        Vivek College of Commerce
                        (Autonomous) has been received.
                    </p>

                    <p>
                        <b>Student ID:</b>
                        ${escapeHtml(sid)}
                    </p>

                    <p>
                        <b>Status:</b>
                        Pending Verification
                    </p>

                    <p>
                        Your Digital ID Card will become
                        available after college staff
                        approve your registration.
                    </p>
                    `
                );
            } catch (mailError) {
                console.warn(
                    "Student confirmation email failed:",
                    mailError.message
                );
            }

            const teachers =
                await db.query(
                    `
                    SELECT email
                    FROM teachers
                    WHERE status='active'
                    `
                );

            const notice = `
                <p>
                    New student registration received.
                </p>

                <p>
                    <b>Name:</b>
                    ${escapeHtml(fields.name)}
                    <br>

                    <b>Student ID:</b>
                    ${escapeHtml(sid)}
                    <br>

                    <b>Email:</b>
                    ${escapeHtml(fields.email)}
                    <br>

                    <b>Phone:</b>
                    ${escapeHtml(fields.phone)}
                    <br>

                    <b>Course:</b>
                    ${escapeHtml(fields.course)}
                    <br>

                    <b>Division:</b>
                    ${escapeHtml(
                        fields.division || "-"
                    )}
                    <br>

                    <b>Year:</b>
                    ${escapeHtml(
                        fields.year_name || "-"
                    )}
                    <br>

                    <b>Status:</b>
                    Pending Verification
                </p>
            `;

            for (
                const teacher of
                teachers.rows
            ) {
                try {
                    await mail(
                        teacher.email,
                        "Pending Student — VeriCampus",
                        notice
                    );
                } catch (mailError) {
                    console.warn(
                        "Teacher notification failed:",
                        mailError.message
                    );
                }
            }

            if (admin) {
                try {
                    await mail(
                        admin,
                        "New Student Registration — VeriCampus",
                        notice
                    );
                } catch (mailError) {
                    console.warn(
                        "Admin notification failed:",
                        mailError.message
                    );
                }
            }

            return res.status(201).json({
                message:
                    "Registration successful. Your Student ID has been sent to your email.",

                studentId:
                    result.rows[0]
                        .student_id,

                id:
                    result.rows[0].id,

                name:
                    result.rows[0].name,

                email:
                    result.rows[0].email,

                phone:
                    result.rows[0].phone,

                course:
                    result.rows[0].course,

                division:
                    result.rows[0]
                        .division || "",

                year_name:
                    result.rows[0]
                        .year_name || "",

                photo:
                    result.rows[0]
                        .photo_path,

                status:
                    result.rows[0].status,

                verified_at:
                    result.rows[0]
                        .verified_at
            });
        } catch (error) {
            if (req.file?.path) {
                fs.unlink(
                    req.file.path,
                    () => {}
                );
            }

            console.error(
                "Student registration error:",
                error.message
            );

            return res.status(400).json({
                message:
                    error.message ||
                    "Student registration failed"
            });
        }
    }
);

// -------------------------------------------------
// STUDENT LOGIN — REQUEST OTP
// -------------------------------------------------

app.post(
    "/api/student/login/request-otp",
    authLimiter,
    async (req, res) => {
        try {
            const studentIdValue =
                cleanText(
                    req.body.studentId,
                    20
                );

            const email =
                cleanEmail(
                    req.body.email
                );

            if (
                !STUDENT_ID_RE.test(
                    studentIdValue
                ) ||
                !EMAIL_RE.test(email)
            ) {
                return res.status(400).json({
                    message:
                        "Enter a valid Student ID and registered email."
                });
            }

            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        student_id,
                        name,
                        email,
                        status
                    FROM students
                    WHERE student_id=$1
                    AND email=$2
                    LIMIT 1
                    `,
                    [
                        studentIdValue,
                        email
                    ]
                );

            // Generic response prevents account enumeration.
            if (!rows.length) {
                return res.json({
                    message:
                        "If the details match a registered student, an OTP has been sent to the registered email."
                });
            }

            const otp =
                otpCode();

            const hash =
                await bcrypt.hash(
                    otp,
                    10
                );

            const expiresAt =
                new Date(
                    Date.now() +
                        10 * 60 * 1000
                );

            await db.query(
                `
                DELETE FROM login_otps
                WHERE student_id=$1
                OR expires_at < CURRENT_TIMESTAMP
                `,
                [studentIdValue]
            );

            await db.query(
                `
                INSERT INTO login_otps
                (
                    student_id,
                    otp_hash,
                    expires_at,
                    attempts
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    0
                )
                `,
                [
                    studentIdValue,
                    hash,
                    expiresAt
                ]
            );

            try {
                await mail(
                    email,
                    "Your VeriCampus Login OTP",
                    `
                    <p>
                        Hi
                        <b>
                            ${escapeHtml(
                                rows[0].name
                            )}
                        </b>,
                    </p>

                    <p>
                        Your one-time
                        VeriCampus login code is:
                    </p>

                    <p
                        style="
                            font-size:28px;
                            letter-spacing:6px
                        "
                    >
                        <b>${otp}</b>
                    </p>

                    <p>
                        This code expires in
                        10 minutes and can only
                        be used once.
                    </p>
                    `
                );
            } catch (mailError) {
                await db.query(
                    `
                    DELETE FROM login_otps
                    WHERE student_id=$1
                    `,
                    [studentIdValue]
                );

                console.warn(
                    "Student OTP email failed:",
                    mailError.message
                );

                return res.status(503).json({
                    message:
                        "Unable to send OTP right now. Please try again later."
                });
            }

            return res.json({
                message:
                    "If the details match a registered student, an OTP has been sent to the registered email."
            });
        } catch (error) {
            console.error(
                "Student OTP request error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Unable to start student login"
            });
        }
    }
);

// -------------------------------------------------
// STUDENT LOGIN — VERIFY OTP
// -------------------------------------------------

app.post(
    "/api/student/login/verify-otp",
    authLimiter,
    async (req, res) => {
        try {
            const studentIdValue =
                cleanText(
                    req.body.studentId,
                    20
                );

            const email =
                cleanEmail(
                    req.body.email
                );

            const otp =
                cleanText(
                    req.body.otp,
                    6
                );

            if (
                !STUDENT_ID_RE.test(
                    studentIdValue
                ) ||
                !EMAIL_RE.test(email) ||
                !/^\d{6}$/.test(otp)
            ) {
                return res.status(400).json({
                    message:
                        "Enter Student ID, registered email and the 6-digit OTP."
                });
            }

            /*
             * FIX:
             * Fetch the COMPLETE student profile here.
             * Earlier version returned only id/name/email/status.
             *
             * The frontend needs photo, course, division,
             * year and verified_at to build the ID card.
             */

            const studentResult =
                await db.query(
                    `
                    SELECT
                        id,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_by,
                        verified_at,
                        created_at
                    FROM students
                    WHERE student_id=$1
                    AND email=$2
                    LIMIT 1
                    `,
                    [
                        studentIdValue,
                        email
                    ]
                );

            if (
                !studentResult.rows.length
            ) {
                return res.status(401).json({
                    message:
                        "Invalid login details or OTP"
                });
            }

            const otpResult =
                await db.query(
                    `
                    SELECT
                        id,
                        otp_hash,
                        expires_at,
                        attempts
                    FROM login_otps
                    WHERE student_id=$1
                    ORDER BY created_at DESC
                    LIMIT 1
                    `,
                    [studentIdValue]
                );

            if (!otpResult.rows.length) {
                return res.status(401).json({
                    message:
                        "OTP expired. Please request a new OTP."
                });
            }

            const otpRow =
                otpResult.rows[0];

            if (
                new Date(
                    otpRow.expires_at
                ).getTime() <
                Date.now()
            ) {
                await db.query(
                    `
                    DELETE FROM login_otps
                    WHERE id=$1
                    `,
                    [otpRow.id]
                );

                return res.status(401).json({
                    message:
                        "OTP expired. Please request a new OTP."
                });
            }

            if (
                otpRow.attempts >= 5
            ) {
                await db.query(
                    `
                    DELETE FROM login_otps
                    WHERE id=$1
                    `,
                    [otpRow.id]
                );

                return res.status(429).json({
                    message:
                        "Too many OTP attempts. Please request a new OTP."
                });
            }

            const valid =
                await bcrypt.compare(
                    otp,
                    otpRow.otp_hash
                );

            if (!valid) {
                await db.query(
                    `
                    UPDATE login_otps
                    SET attempts=attempts+1
                    WHERE id=$1
                    `,
                    [otpRow.id]
                );

                return res.status(401).json({
                    message:
                        "Invalid OTP"
                });
            }

            // OTP can only be used once.
            await db.query(
                `
                DELETE FROM login_otps
                WHERE id=$1
                `,
                [otpRow.id]
            );

            const student =
                studentResult.rows[0];

            const token =
                signToken(
                    {
                        id: student.id,
                        student_id:
                            student.student_id,
                        role: "student"
                    },
                    "2h"
                );

            /*
             * IMPORTANT FIX:
             * Return complete student information.
             *
             * Frontend can now directly decide:
             *
             * status === "pending"
             *     -> show pending message
             *
             * status === "approved"
             *     -> show ID card
             */

            return res.json({
                message:
                    "Student login successful",

                token,

                student: {
                    id: student.id,

                    student_id:
                        student.student_id,

                    studentId:
                        student.student_id,

                    name:
                        student.name,

                    email:
                        student.email,

                    phone:
                        student.phone,

                    course:
                        student.course,

                    division:
                        student.division || "",

                    year_name:
                        student.year_name || "",

                    photo:
                        student.photo_path,

                    photo_path:
                        student.photo_path,

                    status:
                        student.status,

                    verified_by:
                        student.verified_by,

                    verified_at:
                        student.verified_at,

                    created_at:
                        student.created_at
                }
            });
        } catch (error) {
            console.error(
                "Student OTP verification error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Student login failed"
            });
        }
    }
);

// -------------------------------------------------
// LOGGED-IN STUDENT PROFILE
// -------------------------------------------------

app.get(
    "/api/student/me",
    studentAuth,
    async (req, res) => {
        try {
            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_by,
                        verified_at,
                        created_at
                    FROM students
                    WHERE id=$1
                    `,
                    [req.user.id]
                );

            if (!rows.length) {
                return res.status(404).json({
                    message:
                        "Student profile not found"
                });
            }

            const student =
                rows[0];

            /*
             * Return aliases also so older frontend
             * code using studentId/photo continues
             * to work.
             */

            return res.json({
                id:
                    student.id,

                student_id:
                    student.student_id,

                studentId:
                    student.student_id,

                name:
                    student.name,

                email:
                    student.email,

                phone:
                    student.phone,

                course:
                    student.course,

                division:
                    student.division || "",

                year_name:
                    student.year_name || "",

                photo:
                    student.photo_path,

                photo_path:
                    student.photo_path,

                status:
                    student.status,

                verified_by:
                    student.verified_by,

                verified_at:
                    student.verified_at,

                created_at:
                    student.created_at
            });
        } catch (error) {
            console.error(
                "Student profile error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Student profile load failed"
            });
        }
    }
);

// -------------------------------------------------
// TEACHER — ALL STUDENTS
// -------------------------------------------------

app.get(
    "/api/students/all",
    teacherAuth,
    async (_req, res) => {
        try {
            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        photo_path,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        status,
                        verified_by,
                        verified_at,
                        created_at
                    FROM students
                    ORDER BY created_at DESC
                    `
                );

            return res.json(
                rows
            );
        } catch (error) {
            console.error(
                "All students error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Could not load students"
            });
        }
    }
);

// -------------------------------------------------
// TEACHER — PENDING STUDENTS
// -------------------------------------------------

app.get(
    "/api/students/pending",
    teacherAuth,
    async (_req, res) => {
        try {
            const { rows } =
                await db.query(
                    `
                    SELECT
                        id,
                        photo_path,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        status,
                        created_at
                    FROM students
                    WHERE status='pending'
                    ORDER BY created_at DESC
                    `
                );

            return res.json(
                rows
            );
        } catch (error) {
            console.error(
                "Pending students error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Could not load pending students"
            });
        }
    }
);
// -------------------------------------------------
// TEACHER — SINGLE STUDENT
// -------------------------------------------------

app.get(
    "/api/student/:id",
    teacherAuth,
    async (req, res) => {
        try {
            const studentDbId = Number(req.params.id);

            if (
                !Number.isInteger(studentDbId) ||
                studentDbId < 1
            ) {
                return res.status(400).json({
                    message: "Invalid student ID"
                });
            }

            const { rows } = await db.query(
                `
                SELECT
                    id,
                    student_id,
                    name,
                    email,
                    phone,
                    course,
                    division,
                    year_name,
                    photo_path,
                    status,
                    verified_by,
                    verified_at,
                    created_at
                FROM students
                WHERE id=$1
                LIMIT 1
                `,
                [studentDbId]
            );

            if (!rows.length) {
                return res.status(404).json({
                    message: "Student not found"
                });
            }

            const s = rows[0];

            return res.json({
                id: s.id,
                student_id: s.student_id,
                studentId: s.student_id,
                name: s.name,
                email: s.email,
                phone: s.phone,
                course: s.course,
                division: s.division || "",
                year_name: s.year_name || "",
                photo: s.photo_path,
                photo_path: s.photo_path,
                status: s.status,
                verified_by: s.verified_by,
                verified_at: s.verified_at,
                created_at: s.created_at
            });

        } catch (error) {
            console.error(
                "Single student load error:",
                error.message
            );

            return res.status(500).json({
                message: "Could not load student"
            });
        }
    }
);
// -------------------------------------------------
// TEACHER — EDIT STUDENT
// -------------------------------------------------

app.put(
    "/api/student/:id",
    teacherAuth,
    upload.single("photo"),
    async (req, res) => {
        try {
            const studentDbId =
                Number(req.params.id);

            if (
                !Number.isInteger(
                    studentDbId
                ) ||
                studentDbId < 1
            ) {
                return res.status(400).json({
                    message:
                        "Invalid student ID"
                });
            }

            const fields =
                validateStudentFields(
                    req.body
                );

            const currentResult =
                await db.query(
                    `
                    SELECT *
                    FROM students
                    WHERE id=$1
                    `,
                    [studentDbId]
                );

            if (
                !currentResult.rows.length
            ) {
                if (req.file?.path) {
                    fs.unlink(
                        req.file.path,
                        () => {}
                    );
                }

                return res.status(404).json({
                    message:
                        "Student not found"
                });
            }

            const duplicate =
                await db.query(
                    `
                    SELECT id
                    FROM students
                    WHERE email=$1
                    AND id<>$2
                    `,
                    [
                        fields.email,
                        studentDbId
                    ]
                );

            if (
                duplicate.rows.length
            ) {
                if (req.file?.path) {
                    fs.unlink(
                        req.file.path,
                        () => {}
                    );
                }

                return res.status(409).json({
                    message:
                        "Email already registered"
                });
            }

            const current =
                currentResult.rows[0];

            const photoPath =
                req.file
                    ? "/uploads/" +
                      req.file.filename
                    : current.photo_path;

            const result =
                await db.query(
                    `
                    UPDATE students
                    SET
                        name=$1,
                        email=$2,
                        phone=$3,
                        course=$4,
                        division=$5,
                        year_name=$6,
                        photo_path=$7
                    WHERE id=$8
                    RETURNING
                        id,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_at
                    `,
                    [
                        fields.name,
                        fields.email,
                        fields.phone,
                        fields.course,
                        fields.division,
                        fields.year_name,
                        photoPath,
                        studentDbId
                    ]
                );

            if (
                req.file &&
                current.photo_path
            ) {
                const oldFile =
                    path.join(
                        __dirname,
                        "..",
                        current.photo_path.replace(
                            /^\/+/,
                            ""
                        )
                    );

                if (
                    oldFile !==
                    req.file.path
                ) {
                    fs.unlink(
                        oldFile,
                        () => {}
                    );
                }
            }

            return res.json({
                message:
                    "Student data updated successfully",

                student:
                    result.rows[0]
            });
        } catch (error) {
            if (req.file?.path) {
                fs.unlink(
                    req.file.path,
                    () => {}
                );
            }

            console.error(
                "Student update error:",
                error.message
            );

            return res.status(400).json({
                message:
                    error.message ||
                    "Student update failed"
            });
        }
    }
);

// -------------------------------------------------
// TEACHER — APPROVE STUDENT
// -------------------------------------------------

app.post(
    "/api/student/:id/approve",
    teacherAuth,
    async (req, res) => {
        try {
            const studentDbId =
                Number(req.params.id);

            if (
                !Number.isInteger(
                    studentDbId
                ) ||
                studentDbId < 1
            ) {
                return res.status(400).json({
                    message:
                        "Invalid student ID"
                });
            }

            const current =
                await db.query(
                    `
                    SELECT *
                    FROM students
                    WHERE id=$1
                    `,
                    [studentDbId]
                );

            if (
                !current.rows.length
            ) {
                return res.status(404).json({
                    message:
                        "Student not found"
                });
            }

            const student =
                current.rows[0];

            /*
             * IMPORTANT:
             * Explicitly change pending -> approved.
             */

            const result =
                await db.query(
                    `
                    UPDATE students
                    SET
                        status='approved',
                        verified_by=$1,
                        verified_at=CURRENT_TIMESTAMP
                    WHERE id=$2
                    RETURNING
                        id,
                        student_id,
                        name,
                        email,
                        phone,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_by,
                        verified_at,
                        created_at
                    `,
                    [
                        req.user.id,
                        studentDbId
                    ]
                );

            const approvedStudent =
                result.rows[0];

            try {
                await mail(
                    student.email,
                    "Your Digital ID Card Has Been Approved — VeriCampus",
                    `
                    <p>
                        Hi
                        <b>
                            ${escapeHtml(
                                student.name
                            )}
                        </b>,
                    </p>

                    <p>
                        Your VeriCampus Digital ID Card
                        has been
                        <b>
                            approved and activated
                        </b>
                        by college staff.
                    </p>

                    <p>
                        <b>Student ID:</b>
                        ${escapeHtml(
                            student.student_id
                        )}
                    </p>

                    <p>
                        You can now log in to
                        VeriCampus and access
                        your Digital ID Card.
                    </p>
                    `
                );
            } catch (mailError) {
                console.warn(
                    "Approval email failed:",
                    mailError.message
                );
            }

            /*
             * FIX:
             * Return the complete approved student.
             *
             * Teacher dashboard can immediately
             * open the View ID Card without needing
             * another incomplete response.
             */

            return res.json({
                message:
                    "Student approved successfully.",

                student: {
                    id:
                        approvedStudent.id,

                    student_id:
                        approvedStudent.student_id,

                    studentId:
                        approvedStudent.student_id,

                    name:
                        approvedStudent.name,

                    email:
                        approvedStudent.email,

                    phone:
                        approvedStudent.phone,

                    course:
                        approvedStudent.course,

                    division:
                        approvedStudent.division ||
                        "",

                    year_name:
                        approvedStudent.year_name ||
                        "",

                    photo:
                        approvedStudent.photo_path,

                    photo_path:
                        approvedStudent.photo_path,

                    status:
                        approvedStudent.status,

                    verified_by:
                        approvedStudent.verified_by,

                    verified_at:
                        approvedStudent.verified_at,

                    created_at:
                        approvedStudent.created_at
                },

                verified_at:
                    approvedStudent.verified_at
            });
        } catch (error) {
            console.error(
                "Student approval error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Student approval failed"
            });
        }
    }
);

// -------------------------------------------------
// PUBLIC QR / DIGITAL ID PROFILE
// -------------------------------------------------

app.get(
    "/api/student/profile/:student_id",
    async (req, res) => {
        try {
            const studentIdValue =
                cleanText(
                    req.params.student_id,
                    20
                );

            if (
                !STUDENT_ID_RE.test(
                    studentIdValue
                )
            ) {
                return res.status(400).json({
                    message:
                        "Invalid Student ID"
                });
            }

            const { rows } =
                await db.query(
                    `
                    SELECT
                        student_id,
                        name,
                        email,
                        course,
                        division,
                        year_name,
                        photo_path,
                        status,
                        verified_at,
                        created_at
                    FROM students
                    WHERE student_id=$1
                    LIMIT 1
                    `,
                    [studentIdValue]
                );

            if (!rows.length) {
                return res.status(404).json({
                    message:
                        "Student not found"
                });
            }

            /*
             * Only APPROVED students can expose
             * their Digital ID publicly.
             */

            if (
                rows[0].status !==
                "approved"
            ) {
                return res.status(403).json({
                    message:
                        "Student ID card is not yet activated",
                    status:
                        rows[0].status
                });
            }

            return res.json({
                student_id:
                    rows[0].student_id,

                studentId:
                    rows[0].student_id,

                name:
                    rows[0].name,

                email:
                    rows[0].email,

                course:
                    rows[0].course,

                division:
                    rows[0].division || "",

                year_name:
                    rows[0].year_name || "",

                photo:
                    rows[0].photo_path,

                photo_path:
                    rows[0].photo_path,

                status:
                    rows[0].status,

                verified_at:
                    rows[0].verified_at,

                created_at:
                    rows[0].created_at
            });
        } catch (error) {
            console.error(
                "Public profile error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Could not load student profile"
            });
        }
    }
);

// -------------------------------------------------
// ATTENDANCE — SCAN
// -------------------------------------------------

app.post(
    "/api/attendance/scan",
    teacherAuth,
    async (req, res) => {
        const studentIdValue =
            cleanText(
                req.body.student_id,
                20
            );

        if (
            !STUDENT_ID_RE.test(
                studentIdValue
            )
        ) {
            return res.status(400).json({
                message:
                    "Valid Student ID is required"
            });
        }

        const client =
            await db.connect();

        try {
            await client.query(
                "BEGIN"
            );

            const studentResult =
                await client.query(
                    `
                    SELECT
                        student_id,
                        name,
                        status
                    FROM students
                    WHERE student_id=$1
                    FOR SHARE
                    `,
                    [studentIdValue]
                );

            if (
                !studentResult.rows.length ||
                studentResult.rows[0]
                    .status !==
                    "approved"
            ) {
                await client.query(
                    "ROLLBACK"
                );

                return res.status(404).json({
                    message:
                        "Student ID not found or not approved"
                });
            }

            const today =
                await client.query(
                    `
                    SELECT
                        id,
                        in_time,
                        out_time
                    FROM attendance
                    WHERE student_id=$1
                    AND attendance_date=CURRENT_DATE
                    FOR UPDATE
                    `,
                    [studentIdValue]
                );

            if (!today.rows.length) {
                await client.query(
                    `
                    INSERT INTO attendance
                    (
                        student_id,
                        attendance_date,
                        in_time
                    )
                    VALUES
                    (
                        $1,
                        CURRENT_DATE,
                        CURRENT_TIMESTAMP
                    )
                    `,
                    [studentIdValue]
                );

                await client.query(
                    "COMMIT"
                );

                return res.json({
                    message:
                        "IN marked successfully",

                    status: "IN",

                    student:
                        studentResult
                            .rows[0]
                });
            }

            if (
                !today.rows[0]
                    .out_time
            ) {
                await client.query(
                    `
                    UPDATE attendance
                    SET out_time=CURRENT_TIMESTAMP
                    WHERE id=$1
                    `,
                    [
                        today.rows[0].id
                    ]
                );

                await client.query(
                    "COMMIT"
                );

                return res.json({
                    message:
                        "OUT marked successfully",

                    status: "OUT",

                    student:
                        studentResult
                            .rows[0]
                });
            }

            await client.query(
                "ROLLBACK"
            );

            return res.status(409).json({
                message:
                    "Attendance already has IN and OUT for today",

                status: "COMPLETE",

                student:
                    studentResult
                        .rows[0]
            });
        } catch (error) {
            await client.query(
                "ROLLBACK"
            );

            console.error(
                "Attendance scan error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Attendance could not be saved"
            });
        } finally {
            client.release();
        }
    }
);

// -------------------------------------------------
// ATTENDANCE — GET
// -------------------------------------------------

app.get(
    "/api/attendance",
    teacherAuth,
    async (req, res) => {
        try {
            const date =
                cleanText(
                    req.query.date,
                    10
                );

            if (
                date &&
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    date
                )
            ) {
                return res.status(400).json({
                    message:
                        "Invalid date"
                });
            }

            let query;
            let values = [];

            if (date) {
                query = `
                    SELECT
                        a.student_id,
                        s.name,
                        a.attendance_date,
                        a.in_time,
                        a.out_time
                    FROM attendance a
                    JOIN students s
                        ON s.student_id =
                           a.student_id
                    WHERE
                        a.attendance_date=$1
                    ORDER BY
                        a.in_time
                `;

                values = [date];
            } else {
                query = `
                    SELECT
                        a.student_id,
                        s.name,
                        a.attendance_date,
                        a.in_time,
                        a.out_time
                    FROM attendance a
                    JOIN students s
                        ON s.student_id =
                           a.student_id
                    ORDER BY
                        a.attendance_date DESC,
                        a.in_time DESC
                    LIMIT 500
                `;
            }

            const { rows } =
                await db.query(
                    query,
                    values
                );

            return res.json({
                attendance: rows
            });
        } catch (error) {
            console.error(
                "Attendance loading error:",
                error.message
            );

            return res.status(500).json({
                message:
                    "Could not load attendance"
            });
        }
    }
);

// -------------------------------------------------
// API 404
// -------------------------------------------------

app.use(
    "/api",
    (_req, res) =>
        res.status(404).json({
            message:
                "API endpoint not found"
        })
);

// -------------------------------------------------
// GLOBAL ERROR HANDLING
// -------------------------------------------------

app.use(
    (
        error,
        _req,
        res,
        _next
    ) => {
        console.error(
            "Request error:",
            error.message
        );

        if (
            error instanceof
            multer.MulterError
        ) {
            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {
                return res.status(400).json({
                    message:
                        "Photo size must be less than 5 MB"
                });
            }

            return res.status(400).json({
                message:
                    error.message
            });
        }

        if (
            error.message ===
            "CORS origin not allowed"
        ) {
            return res.status(403).json({
                message:
                    "Origin not allowed"
            });
        }

        if (
            error.message ===
            "Only JPG, PNG and WEBP images are allowed."
        ) {
            return res.status(400).json({
                message:
                    error.message
            });
        }

        return res.status(500).json({
            message:
                "Server error occurred"
        });
    }
);

// -------------------------------------------------
// START SERVER
// -------------------------------------------------

async function startServer() {
    console.log(
        "Starting VeriCampus PostgreSQL backend..."
    );

    await testDatabaseConnection();

    await testEmailConnection();

    app.listen(
        PORT,
        "0.0.0.0",
        () => {
            console.log(
                `VeriCampus server listening on port ${PORT}`
            );

            console.log(
                `Frontend:
http://localhost:${PORT}`
            );
        }
    );
}

startServer().catch(error => {
    console.error(
        "Server startup failed:",
        error.message
    );

    process.exit(1);
});