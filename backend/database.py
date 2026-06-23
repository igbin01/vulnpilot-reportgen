import json
import sqlite3
from datetime import datetime
from config import DATABASE_NAME

DB_NAME = DATABASE_NAME


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            app_type TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            vulnerability_type TEXT NOT NULL,
            affected_endpoint TEXT NOT NULL,
            severity TEXT NOT NULL,
            report_style TEXT NOT NULL,
            output_format TEXT NOT NULL,
            report TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        project_id INTEGER NOT NULL,
        vulnerability_type TEXT NOT NULL,
        affected_endpoint TEXT NOT NULL,
        severity TEXT NOT NULL,
        test_performed TEXT,
        observed_result TEXT,
        impact TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (project_id) REFERENCES projects(id)
    )
""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            profile TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    conn.commit()
    conn.close()


def create_user(username: str, password_hash: str):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        """, (
            username,
            password_hash,
            datetime.now().isoformat(timespec="seconds")
        ))

        conn.commit()
        return cursor.lastrowid

    except sqlite3.IntegrityError:
        return None

    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, password_hash, created_at
        FROM users
        WHERE username = ?
    """, (username,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "created_at": row[3]
    }


def update_user_password(user_id: int, password_hash: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (password_hash, user_id))

    updated = cursor.rowcount
    conn.commit()
    conn.close()

    return updated > 0


def create_password_reset_token(user_id: int, token: str, expires_at: str):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat(timespec="seconds")

    cursor.execute("""
        UPDATE password_reset_tokens
        SET used_at = ?
        WHERE user_id = ? AND used_at IS NULL
    """, (now, user_id))

    cursor.execute("""
        INSERT INTO password_reset_tokens (
            user_id,
            token,
            expires_at,
            created_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        user_id,
        token,
        expires_at,
        now
    ))

    conn.commit()
    reset_id = cursor.lastrowid
    conn.close()

    return reset_id


def get_password_reset_token(token: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            user_id,
            token,
            expires_at,
            used_at,
            created_at
        FROM password_reset_tokens
        WHERE token = ?
    """, (token,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "user_id": row[1],
        "token": row[2],
        "expires_at": row[3],
        "used_at": row[4],
        "created_at": row[5]
    }


def mark_password_reset_token_used(reset_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE password_reset_tokens
        SET used_at = ?
        WHERE id = ?
    """, (
        datetime.now().isoformat(timespec="seconds"),
        reset_id
    ))

    updated = cursor.rowcount
    conn.commit()
    conn.close()

    return updated > 0


def create_project(user_id: int, data):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO projects (
            user_id,
            name,
            target_url,
            app_type,
            auth_type,
            description,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        data.name,
        data.target_url,
        data.app_type,
        data.auth_type,
        data.description,
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    project_id = cursor.lastrowid
    conn.close()

    return project_id


def get_projects(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            target_url,
            app_type,
            auth_type,
            description,
            created_at
        FROM projects
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "name": row[1],
            "target_url": row[2],
            "app_type": row[3],
            "auth_type": row[4],
            "description": row[5],
            "created_at": row[6]
        }
        for row in rows
    ]


def get_project_by_id(user_id: int, project_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            target_url,
            app_type,
            auth_type,
            description,
            created_at
        FROM projects
        WHERE user_id = ? AND id = ?
    """, (user_id, project_id))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "name": row[1],
        "target_url": row[2],
        "app_type": row[3],
        "auth_type": row[4],
        "description": row[5],
        "created_at": row[6]
    }


def delete_project(user_id: int, project_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id
            FROM projects
            WHERE user_id = ? AND id = ?
        """, (user_id, project_id))

        if not cursor.fetchone():
            return False

        cursor.execute("""
            DELETE FROM findings
            WHERE user_id = ? AND project_id = ?
        """, (user_id, project_id))

        cursor.execute("""
            DELETE FROM scans
            WHERE user_id = ? AND project_id = ?
        """, (user_id, project_id))

        cursor.execute("""
            DELETE FROM reports
            WHERE user_id = ? AND project_id = ?
        """, (user_id, project_id))

        cursor.execute("""
            DELETE FROM projects
            WHERE user_id = ? AND id = ?
        """, (user_id, project_id))

        conn.commit()
        return cursor.rowcount > 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_report(user_id: int, project_id: int, data, report: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO reports (
            user_id,
            project_id,
            vulnerability_type,
            affected_endpoint,
            severity,
            report_style,
            output_format,
            report,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        project_id,
        data.vulnerability_type,
        data.affected_endpoint,
        data.severity,
        data.report_style,
        data.output_format,
        report,
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    report_id = cursor.lastrowid
    conn.close()

    return report_id


def get_reports(user_id: int, project_id: int = None):
    conn = get_connection()
    cursor = conn.cursor()

    if project_id:
        cursor.execute("""
            SELECT 
                id,
                project_id,
                vulnerability_type,
                affected_endpoint,
                severity,
                report_style,
                output_format,
                created_at
            FROM reports
            WHERE user_id = ? AND project_id = ?
            ORDER BY id DESC
        """, (user_id, project_id))
    else:
        cursor.execute("""
            SELECT 
                id,
                project_id,
                vulnerability_type,
                affected_endpoint,
                severity,
                report_style,
                output_format,
                created_at
            FROM reports
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "project_id": row[1],
            "vulnerability_type": row[2],
            "affected_endpoint": row[3],
            "severity": row[4],
            "report_style": row[5],
            "output_format": row[6],
            "created_at": row[7]
        }
        for row in rows
    ]


def get_report_by_id(user_id: int, report_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            id,
            project_id,
            vulnerability_type,
            affected_endpoint,
            severity,
            report_style,
            output_format,
            report,
            created_at
        FROM reports
        WHERE user_id = ? AND id = ?
    """, (user_id, report_id))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "project_id": row[1],
        "vulnerability_type": row[2],
        "affected_endpoint": row[3],
        "severity": row[4],
        "report_style": row[5],
        "output_format": row[6],
        "report": row[7],
        "created_at": row[8]
    }


def save_scan(user_id: int, project_id: int, target_url: str, profile: str, result: dict):
    conn = get_connection()
    cursor = conn.cursor()
    summary = result.get("summary", {})

    cursor.execute("""
        INSERT INTO scans (
            user_id,
            project_id,
            target_url,
            status,
            profile,
            summary_json,
            result_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        project_id,
        target_url,
        "completed",
        profile,
        json.dumps(summary),
        json.dumps(result),
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    return scan_id


def get_scans_by_project(user_id: int, project_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            project_id,
            target_url,
            status,
            profile,
            summary_json,
            created_at
        FROM scans
        WHERE user_id = ? AND project_id = ?
        ORDER BY id DESC
    """, (user_id, project_id))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "project_id": row[1],
            "target_url": row[2],
            "status": row[3],
            "profile": row[4],
            "summary": json.loads(row[5]),
            "created_at": row[6]
        }
        for row in rows
    ]


def get_scan_by_id(user_id: int, scan_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            project_id,
            target_url,
            status,
            profile,
            summary_json,
            result_json,
            created_at
        FROM scans
        WHERE user_id = ? AND id = ?
    """, (user_id, scan_id))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "project_id": row[1],
        "target_url": row[2],
        "status": row[3],
        "profile": row[4],
        "summary": json.loads(row[5]),
        "result": json.loads(row[6]),
        "created_at": row[7]
    }


def get_full_reports_by_project(user_id: int, project_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT report
        FROM reports
        WHERE user_id = ? AND project_id = ?
        ORDER BY id ASC
    """, (user_id, project_id))

    rows = cursor.fetchall()
    conn.close()

    return [row[0] for row in rows]


def create_finding(user_id: int, project_id: int, data):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO findings (
            user_id,
            project_id,
            vulnerability_type,
            affected_endpoint,
            severity,
            test_performed,
            observed_result,
            impact,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        project_id,
        data.vulnerability_type,
        data.affected_endpoint,
        data.severity,
        data.test_performed,
        data.observed_result,
        data.impact,
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
    finding_id = cursor.lastrowid
    conn.close()

    return finding_id


def get_findings_by_project(user_id: int, project_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            project_id,
            vulnerability_type,
            affected_endpoint,
            severity,
            test_performed,
            observed_result,
            impact,
            created_at
        FROM findings
        WHERE user_id = ? AND project_id = ?
        ORDER BY id DESC
    """, (user_id, project_id))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "project_id": row[1],
            "vulnerability_type": row[2],
            "affected_endpoint": row[3],
            "severity": row[4],
            "test_performed": row[5],
            "observed_result": row[6],
            "impact": row[7],
            "created_at": row[8]
        }
        for row in rows
    ]


def get_finding_by_id(user_id: int, finding_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            project_id,
            vulnerability_type,
            affected_endpoint,
            severity,
            test_performed,
            observed_result,
            impact,
            created_at
        FROM findings
        WHERE user_id = ? AND id = ?
    """, (user_id, finding_id))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "project_id": row[1],
        "vulnerability_type": row[2],
        "affected_endpoint": row[3],
        "severity": row[4],
        "test_performed": row[5],
        "observed_result": row[6],
        "impact": row[7],
        "created_at": row[8]
    }


def delete_finding(user_id: int, finding_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM findings
        WHERE user_id = ? AND id = ?
    """, (user_id, finding_id))

    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    return deleted > 0
