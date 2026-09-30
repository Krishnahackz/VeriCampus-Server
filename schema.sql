-- VeriCampus PostgreSQL schema
-- Run this against your PostgreSQL database (for example, Render PostgreSQL).

CREATE TABLE IF NOT EXISTS teachers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    access_code_hash VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'teacher' CHECK (role = 'teacher'),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    phone VARCHAR(20) NOT NULL,
    course VARCHAR(100) NOT NULL,
    division VARCHAR(20),
    year_name VARCHAR(30),
    photo_path VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
    verified_by BIGINT REFERENCES teachers(id) ON DELETE SET NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attendance (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
    attendance_date DATE NOT NULL,
    in_time TIMESTAMPTZ NOT NULL,
    out_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uniq_student_day UNIQUE (student_id, attendance_date)
);

CREATE TABLE IF NOT EXISTS login_otps (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
    otp_hash VARCHAR(100) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_students_status ON students(status);
CREATE INDEX IF NOT EXISTS idx_students_created_at ON students(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date DESC);
CREATE INDEX IF NOT EXISTS idx_login_otps_student ON login_otps(student_id);
CREATE INDEX IF NOT EXISTS idx_login_otps_expiry ON login_otps(expires_at);
