import sqlite3
import os
import hashlib
from datetime import datetime

# 导入日志模块
from logging_config import app_logger


def init_db():
    """初始化数据库"""
    try:
        # 记录开始初始化
        app_logger.info("开始初始化数据库...")

        if os.path.exists('dormitory.db'):
            os.remove('dormitory.db')
            app_logger.info("已删除旧数据库文件")

        conn = sqlite3.connect('dormitory.db')
        cursor = conn.cursor()

        # 创建用户表 - 使用datetime('now', 'localtime')获取本地时间
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            name TEXT,
            student_id TEXT UNIQUE NOT NULL,
            gender TEXT,
            age INTEGER,
            major TEXT,
            phone TEXT,
            dormitory_id INTEGER,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (dormitory_id) REFERENCES dormitories (id)
        )
        ''')
        app_logger.debug("创建用户表成功")

        # 创建宿舍表
        cursor.execute('''
        CREATE TABLE dormitories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            building TEXT NOT NULL,
            room_number TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            current_occupancy INTEGER DEFAULT 0,
            status TEXT DEFAULT 'available',
            description TEXT,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
        )
        ''')
        app_logger.debug("创建宿舍表成功")

        # 创建申请记录表
        cursor.execute('''
        CREATE TABLE applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            dormitory_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            apply_date TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            processed_date TIMESTAMP,
            admin_notes TEXT,
            FOREIGN KEY (student_id) REFERENCES users (id),
            FOREIGN KEY (dormitory_id) REFERENCES dormitories (id)
        )
        ''')
        app_logger.debug("创建申请记录表成功")

        # 创建公告表
        cursor.execute('''
        CREATE TABLE announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            admin_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (admin_id) REFERENCES users (id)
        )
        ''')
        app_logger.debug("创建公告表成功")

        # 创建问题反馈表
        cursor.execute('''
        CREATE TABLE feedbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            resolved_at TIMESTAMP,
            admin_response TEXT,
            category TEXT DEFAULT 'other',
            FOREIGN KEY (student_id) REFERENCES users (id)
        )
        ''')
        app_logger.debug("创建问题反馈表成功")

        # 插入默认管理员账户
        cursor.execute(
            "INSERT INTO users (username, password, role, name, student_id) VALUES (?, ?, ?, ?, ?)",
            ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin', '系统管理员', 'admin')
        )
        app_logger.info("插入默认管理员账户成功")

        # 插入一些示例宿舍数据
        sample_dorms = [
            ('A栋', '101', 4, 0, '四人间，独立卫浴'),
            ('A栋', '102', 4, 0, '四人间，独立卫浴'),
            ('A栋', '103', 4, 0, '四人间，独立卫浴'),
            ('B栋', '201', 6, 0, '六人间，公共卫浴'),
            ('B栋', '202', 6, 0, '六人间，公共卫浴'),
            ('C栋', '301', 2, 0, '双人间，独立卫浴，空调'),
        ]

        for dorm in sample_dorms:
            cursor.execute(
                "INSERT INTO dormitories (building, room_number, capacity, current_occupancy, description) VALUES (?, ?, ?, ?, ?)",
                dorm
            )
        app_logger.info(f"插入{len(sample_dorms)}个示例宿舍数据成功")

        conn.commit()
        conn.close()

        app_logger.info("数据库初始化完成！")
        return True

    except Exception as e:
        app_logger.error(f"数据库初始化失败: {str(e)}")
        raise


def hash_password(password):
    """密码加密"""
    try:
        return hashlib.sha256(password.encode()).hexdigest()
    except Exception as e:
        app_logger.error(f"密码加密失败: {str(e)}")
        raise


if __name__ == '__main__':
    init_db()