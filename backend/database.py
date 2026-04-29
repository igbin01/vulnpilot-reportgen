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