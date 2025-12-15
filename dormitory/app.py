from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
import sqlite3
import hashlib
import os
from datetime import datetime
import traceback

# 导入日志模块
from logging_config import app_logger, audit_logger

app = Flask(__name__, template_folder='templates')
app.secret_key = 'dormitory_management_system_secret_key_2023'
DATABASE = 'dormitory.db'


# 数据库连接辅助函数
def get_db_connection():
    """获取数据库连接"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        app_logger.error(f"数据库连接失败: {str(e)}")
        raise


# 密码加密
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# 登录检查装饰器
def login_required(role=None):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                app_logger.warning(f"未登录访问: {request.path}")
                return jsonify({'success': False, 'message': '请先登录'})
            if role and session.get('role') != role:
                user_info = f"用户ID: {session.get('user_id')}, 角色: {session.get('role')}"
                app_logger.warning(f"权限不足: {user_info} 尝试访问 {request.path}")
                return jsonify({'success': False, 'message': '权限不足'})
            return f(*args, **kwargs)

        decorated_function.__name__ = f.__name__
        return decorated_function

    return decorator


# 格式化日期时间为字符串
def format_datetime(dt):
    """格式化日期时间为字符串"""
    if dt is None:
        return None

    # 如果是字符串，直接返回
    if isinstance(dt, str):
        # 检查是否已经是正确格式
        if ' ' in dt and '-' in dt and ':' in dt:
            return dt
        # 如果不是标准格式，尝试转换
        try:
            # 尝试解析为datetime对象
            if 'T' in dt:  # ISO格式
                dt_obj = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            else:
                # 尝试常见格式
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d']:
                    try:
                        dt_obj = datetime.strptime(dt, fmt)
                        break
                    except:
                        continue
                else:
                    return dt  # 无法解析，返回原字符串

            # 格式化为标准字符串
            return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return dt

    # 如果是datetime对象，直接格式化
    try:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        # 其他情况转换为字符串
        return str(dt)


# 简单的数据库初始化函数
def init_db_simple():
    """初始化数据库"""
    try:
        if not os.path.exists(DATABASE):
            app_logger.info("数据库不存在，正在初始化...")

            from database import init_db
            init_db()

            app_logger.info("数据库初始化完成！")
    except Exception as e:
        app_logger.error(f"数据库初始化失败: {str(e)}")
        raise


# HTTP请求日志中间件
@app.before_request
def before_request():
    """记录HTTP请求信息"""
    if request.path != '/favicon.ico':
        if request.path.startswith('/api/'):
            user_info = f"用户ID: {session.get('user_id', '未登录')}"
            app_logger.info(f"请求: {request.method} {request.path} - {user_info}")


@app.after_request
def after_request(response):
    """记录HTTP响应信息"""
    if request.path != '/favicon.ico' and request.path.startswith('/api/'):
        app_logger.info(f"响应: {request.method} {request.path} - 状态码: {response.status_code}")
    return response


# favicon.ico 处理
@app.route('/favicon.ico')
def favicon():
    try:
        # 如果存在favicon.ico文件，则返回
        if os.path.exists('static/favicon.ico'):
            return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')
        # 否则返回204 No Content，避免404错误
        return '', 204
    except Exception as e:
        # 任何错误都返回204，避免产生错误日志
        return '', 204


# 自定义404错误处理
@app.errorhandler(404)
def page_not_found(e):
    """自定义404错误处理"""
    # 如果是API请求，返回JSON格式的错误信息
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'message': '请求的资源不存在'
        }), 404
    # 如果是普通页面请求，返回HTML页面
    elif request.path != '/favicon.ico':  # 避免favicon.ico产生404错误
        app_logger.warning(f"页面不存在: {request.path} - 用户ID: {session.get('user_id', '未登录')}")
    # 对于favicon.ico等资源请求，返回204
    return '', 204


# 错误处理器
@app.errorhandler(Exception)
def handle_exception(e):
    """全局异常处理，过滤favicon.ico的404错误"""
    # 如果404错误且是favicon.ico请求，直接返回204
    if hasattr(e, 'code') and e.code == 404 and request.path == '/favicon.ico':
        return '', 204

    error_message = str(e)
    error_traceback = traceback.format_exc()

    # 获取用户信息
    user_id = session.get('user_id', '未登录')

    # 记录错误信息
    app_logger.error(
        f"异常发生: {error_message}\n"
        f"用户ID: {user_id}\n"
        f"请求: {request.method} {request.path}\n"
        f"追踪信息:\n{error_traceback}"
    )

    # 返回错误响应
    return jsonify({
        'success': False,
        'message': '服务器内部错误，请稍后重试'
    }), 500


# 路由定义
@app.route('/')
def index():
    app_logger.debug("访问首页")
    return render_template('index.html')


# 用户认证相关
@app.route('/api/register', methods=['POST'])
def register():
    """用户注册"""
    try:
        data = request.json
        name = data.get('name')
        gender = data.get('gender')
        age = data.get('age')
        student_id = data.get('student_id')
        major = data.get('major')
        phone = data.get('phone')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        app_logger.info(f"注册尝试: 学号={student_id}, 姓名={name}")

        if not all([name, gender, age, student_id, major, phone, password, confirm_password]):
            app_logger.warning("注册失败: 缺少必填字段")
            return jsonify({'success': False, 'message': '所有字段都是必填的'})

        if password != confirm_password:
            app_logger.warning("注册失败: 两次输入的密码不一致")
            return jsonify({'success': False, 'message': '两次输入的密码不一致'})

        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT * FROM users WHERE student_id = ?', (student_id,)
        ).fetchone()

        if existing_user:
            conn.close()
            app_logger.warning(f"注册失败: 学号 {student_id} 已被注册")
            return jsonify({'success': False, 'message': '该学号已被注册'})

        username = student_id

        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, role, name, student_id, gender, age, major, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, hash_password(password), 'student', name, student_id, gender, age, major, phone)
        )

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # 记录审计日志
        user_info = f"ID: {user_id}, 学号: {student_id}, 姓名: {name}"
        audit_logger.info("用户注册成功", extra={'user_info': user_info})

        app_logger.info(f"用户注册成功: 学号={student_id}, 姓名={name}")
        return jsonify({'success': True, 'message': '注册成功'})

    except Exception as e:
        app_logger.error(f"注册异常: {str(e)}")
        return jsonify({'success': False, 'message': '系统错误，请稍后重试'})


@app.route('/api/login', methods=['POST'])
def login():
    """用户登录"""
    try:
        data = request.json
        student_id = data.get('student_id')
        password = data.get('password')

        app_logger.info(f"登录尝试: 学号={student_id}")

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE student_id = ? AND password = ?',
            (student_id, hash_password(password))
        ).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = user['name']
            session['student_id'] = user['student_id']

            # 记录审计日志
            user_info = f"ID: {user['id']}, 学号: {user['student_id']}, 姓名: {user['name']}, 角色: {user['role']}"
            audit_logger.info("用户登录成功", extra={'user_info': user_info})

            app_logger.info(f"用户登录成功: 学号={student_id}, 角色={user['role']}")
            return jsonify({
                'success': True,
                'message': '登录成功',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'name': user['name'],
                    'student_id': user['student_id']
                }
            })
        else:
            app_logger.warning(f"登录失败: 学号或密码错误 - 学号={student_id}")
            return jsonify({'success': False, 'message': '学号或密码错误'})

    except Exception as e:
        app_logger.error(f"登录异常: {str(e)}")
        return jsonify({'success': False, 'message': '系统错误，请稍后重试'})


@app.route('/api/logout')
def logout():
    """用户登出"""
    try:
        user_info = f"ID: {session.get('user_id', 'N/A')}, 学号: {session.get('student_id', 'N/A')}, 姓名: {session.get('name', 'N/A')}"
        audit_logger.info("用户登出", extra={'user_info': user_info})

        app_logger.info(f"用户登出: {user_info}")
        session.clear()
        return jsonify({'success': True, 'message': '已退出登录'})
    except Exception as e:
        app_logger.error(f"登出异常: {str(e)}")
        return jsonify({'success': False, 'message': '系统错误'})


# 修改密码API
@app.route('/api/change-password', methods=['POST'])
@login_required()
def change_password():
    """修改密码"""
    try:
        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        user_id = session.get('user_id')
        user_name = session.get('name')

        app_logger.info(f"密码修改尝试: 用户ID={user_id}, 姓名={user_name}")

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ? AND password = ?',
            (user_id, hash_password(current_password))
        ).fetchone()

        if not user:
            conn.close()
            app_logger.warning(f"密码修改失败: 当前密码错误 - 用户ID={user_id}")
            return jsonify({'success': False, 'message': '当前密码错误'})

        try:
            conn.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (hash_password(new_password), user_id)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {user_id}, 姓名: {user_name}"
            audit_logger.info("密码修改成功", extra={'user_info': user_info})

            app_logger.info(f"密码修改成功: 用户ID={user_id}")
            return jsonify({'success': True, 'message': '密码修改成功'})
        except Exception as e:
            app_logger.error(f"修改密码错误: {str(e)}, 用户ID={user_id}")
            conn.close()
            return jsonify({'success': False, 'message': '密码修改失败'})

    except Exception as e:
        app_logger.error(f"修改密码API异常: {str(e)}")
        return jsonify({'success': False, 'message': '系统错误'})


# 学生个人信息API
@app.route('/api/student/profile', methods=['GET', 'POST'])
@login_required('student')
def student_profile():
    """学生个人信息管理"""
    try:
        conn = get_db_connection()
        user_id = session.get('user_id')

        if request.method == 'GET':
            app_logger.debug(f"获取学生个人信息: 用户ID={user_id}")

            user = conn.execute('''
                SELECT u.*, d.building, d.room_number 
                FROM users u 
                LEFT JOIN dormitories d ON u.dormitory_id = d.id 
                WHERE u.id = ?
            ''', (user_id,)).fetchone()

            if user is None:
                conn.close()
                app_logger.error(f"用户不存在: 用户ID={user_id}")
                return jsonify({'success': False, 'message': '用户不存在'}), 404

            dormitory_info = "未分配"
            if user['dormitory_id'] and user['building'] and user['room_number']:
                dormitory_info = f"{user['building']}-{user['room_number']}"

            conn.close()
            return jsonify({
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'student_id': user['student_id'],
                'gender': user['gender'],
                'age': user['age'],
                'major': user['major'],
                'phone': user['phone'],
                'dormitory': dormitory_info
            })
        else:
            data = request.json
            app_logger.info(f"更新学生个人信息: 用户ID={user_id}")

            conn.execute(
                'UPDATE users SET name = ?, gender = ?, age = ?, major = ?, phone = ? WHERE id = ?',
                (data.get('name'), data.get('gender'), data.get('age'),
                 data.get('major'), data.get('phone'), user_id)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {user_id}, 学号: {session.get('student_id')}, 姓名: {data.get('name')}"
            audit_logger.info("个人信息更新成功", extra={'user_info': user_info})

            app_logger.info(f"个人信息更新成功: 用户ID={user_id}")
            return jsonify({'success': True, 'message': '个人信息更新成功'})

    except Exception as e:
        app_logger.error(f"学生个人信息API错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '服务器错误'}), 500


# 学生退宿功能
@app.route('/api/student/checkout', methods=['POST'])
@login_required('student')
def student_checkout():
    """学生退宿功能"""
    try:
        conn = get_db_connection()
        user_id = session.get('user_id')
        user_name = session.get('name')

        app_logger.info(f"退宿申请: 用户ID={user_id}, 姓名={user_name}")

        # 获取用户信息（包含宿舍信息）
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if not user or not user['dormitory_id']:
            conn.close()
            app_logger.warning(f"退宿失败: 用户没有宿舍 - 用户ID={user_id}")
            return jsonify({'success': False, 'message': '您当前没有宿舍，无法退宿'})

        dormitory_id = user['dormitory_id']

        # 获取宿舍信息
        dorm = conn.execute(
            'SELECT * FROM dormitories WHERE id = ?',
            (dormitory_id,)
        ).fetchone()

        if not dorm:
            conn.close()
            app_logger.warning(f"退宿失败: 宿舍不存在 - 宿舍ID={dormitory_id}")
            return jsonify({'success': False, 'message': '宿舍不存在，无法退宿'})

        # 开始事务
        cursor = conn.cursor()

        try:
            # 1. 更新宿舍入住人数（确保不会变成负数）
            new_occupancy = max(0, dorm['current_occupancy'] - 1)
            cursor.execute(
                'UPDATE dormitories SET current_occupancy = ? WHERE id = ?',
                (new_occupancy, dormitory_id)
            )

            # 2. 根据入住人数更新宿舍状态
            if new_occupancy >= dorm['capacity']:
                cursor.execute(
                    'UPDATE dormitories SET status = "full" WHERE id = ?',
                    (dormitory_id,)
                )
            elif new_occupancy == 0:
                cursor.execute(
                    'UPDATE dormitories SET status = "available" WHERE id = ?',
                    (dormitory_id,)
                )
            else:
                cursor.execute(
                    'UPDATE dormitories SET status = "available" WHERE id = ?',
                    (dormitory_id,)
                )

            # 3. 清空学生的宿舍信息
            cursor.execute(
                'UPDATE users SET dormitory_id = NULL WHERE id = ?',
                (user_id,)
            )

            # 4. 更新所有相关的申请记录状态
            # 标记所有已批准的申请为已退宿
            cursor.execute(
                'UPDATE applications SET status = "checked_out" WHERE student_id = ? AND status = "approved"',
                (user_id,)
            )

            # 标记所有待处理的申请为取消（因为学生已退宿）
            cursor.execute(
                'UPDATE applications SET status = "cancelled" WHERE student_id = ? AND status = "pending"',
                (user_id,)
            )

            conn.commit()

            # 记录审计日志
            user_info = f"ID: {user_id}, 姓名: {user_name}, 原宿舍: {dorm['building']}-{dorm['room_number']}"
            audit_logger.info("学生退宿成功", extra={'user_info': user_info})

            app_logger.info(f"退宿成功: 用户ID={user_id}, 宿舍={dorm['building']}-{dorm['room_number']}")
            return jsonify({
                'success': True,
                'message': '退宿成功，您的宿舍床位已释放'
            })

        except Exception as e:
            conn.rollback()
            raise e

        finally:
            conn.close()

    except Exception as e:
        app_logger.error(f"退宿操作错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '退宿失败，请稍后重试'})


# 管理员强制退宿功能
@app.route('/api/admin/students/<int:student_id>/checkout', methods=['POST'])
@login_required('admin')
def admin_force_checkout(student_id):
    """管理员强制退宿"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')

        app_logger.info(f"管理员强制退宿: 管理员ID={admin_id}, 学生ID={student_id}")

        conn = get_db_connection()

        # 获取学生信息
        student = conn.execute(
            'SELECT * FROM users WHERE id = ? AND role = "student"',
            (student_id,)
        ).fetchone()

        if not student:
            conn.close()
            app_logger.warning(f"强制退宿失败: 学生不存在 - 学生ID={student_id}")
            return jsonify({'success': False, 'message': '学生不存在'})

        if not student['dormitory_id']:
            conn.close()
            app_logger.warning(f"强制退宿失败: 学生没有宿舍 - 学生ID={student_id}")
            return jsonify({'success': False, 'message': '该学生当前没有宿舍'})

        dormitory_id = student['dormitory_id']

        # 获取宿舍信息用于日志
        dorm = conn.execute(
            'SELECT * FROM dormitories WHERE id = ?',
            (dormitory_id,)
        ).fetchone()

        if not dorm:
            conn.close()
            app_logger.warning(f"强制退宿失败: 宿舍不存在 - 宿舍ID={dormitory_id}")
            return jsonify({'success': False, 'message': '宿舍不存在'})

        # 开始事务
        cursor = conn.cursor()

        try:
            # 1. 更新宿舍入住人数（确保不会变成负数）
            new_occupancy = max(0, dorm['current_occupancy'] - 1)
            cursor.execute(
                'UPDATE dormitories SET current_occupancy = ? WHERE id = ?',
                (new_occupancy, dormitory_id)
            )

            # 2. 根据入住人数更新宿舍状态
            if new_occupancy >= dorm['capacity']:
                cursor.execute(
                    'UPDATE dormitories SET status = "full" WHERE id = ?',
                    (dormitory_id,)
                )
            elif new_occupancy == 0:
                cursor.execute(
                    'UPDATE dormitories SET status = "available" WHERE id = ?',
                    (dormitory_id,)
                )
            else:
                cursor.execute(
                    'UPDATE dormitories SET status = "available" WHERE id = ?',
                    (dormitory_id,)
                )

            # 3. 清空学生的宿舍信息
            cursor.execute(
                'UPDATE users SET dormitory_id = NULL WHERE id = ?',
                (student_id,)
            )

            # 4. 更新所有相关的申请记录状态
            # 标记所有已批准的申请为已退宿
            cursor.execute(
                'UPDATE applications SET status = "checked_out" WHERE student_id = ? AND status = "approved"',
                (student_id,)
            )

            # 标记所有待处理的申请为取消
            cursor.execute(
                'UPDATE applications SET status = "cancelled" WHERE student_id = ? AND status = "pending"',
                (student_id,)
            )

            conn.commit()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            student_info = f"学生ID: {student_id}, 姓名: {student['name']}, 学号: {student['student_id']}, 原宿舍: {dorm['building']}-{dorm['room_number']}"
            audit_logger.info(f"管理员强制退宿: {student_info}", extra={'user_info': user_info})

            app_logger.info(f"强制退宿成功: 学生ID={student_id}, 宿舍={dorm['building']}-{dorm['room_number']}")
            return jsonify({
                'success': True,
                'message': f'强制退宿成功，学生{student["name"]}({student["student_id"]})已从{dorm["building"]}-{dorm["room_number"]}退宿'
            })

        except Exception as e:
            conn.rollback()
            raise e

        finally:
            conn.close()

    except Exception as e:
        app_logger.error(f"强制退宿操作错误: {str(e)}, 学生ID={student_id}")
        return jsonify({'success': False, 'message': '强制退宿失败，请稍后重试'})


# 学生功能
@app.route('/api/student/dormitories')
@login_required('student')
def get_dormitories():
    """获取宿舍列表"""
    try:
        user_id = session.get('user_id')
        app_logger.debug(f"获取宿舍列表: 用户ID={user_id}")

        conn = get_db_connection()
        dormitories = conn.execute(
            'SELECT * FROM dormitories ORDER BY building, room_number'
        ).fetchall()
        conn.close()

        result = []
        for dorm in dormitories:
            result.append({
                'id': dorm['id'],
                'building': dorm['building'],
                'room_number': dorm['room_number'],
                'capacity': dorm['capacity'],
                'current_occupancy': dorm['current_occupancy'],
                'status': dorm['status'],
                'description': dorm['description']
            })

        app_logger.debug(f"获取到 {len(result)} 个宿舍信息")
        return jsonify(result)

    except Exception as e:
        app_logger.error(f"获取宿舍信息错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify([])


@app.route('/api/student/apply', methods=['POST'])
@login_required('student')
def apply_dormitory():
    """申请宿舍"""
    try:
        data = request.json
        dormitory_id = data.get('dormitory_id')
        user_id = session.get('user_id')
        user_name = session.get('name')

        app_logger.info(f"宿舍申请: 用户ID={user_id}, 姓名={user_name}, 宿舍ID={dormitory_id}")

        conn = get_db_connection()

        # 检查学生是否已经有宿舍
        student = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if student and student['dormitory_id']:
            conn.close()
            app_logger.warning(f"申请失败: 用户已有宿舍 - 用户ID={user_id}")
            return jsonify({'success': False, 'message': '您已经有宿舍了，请先退宿再申请其他宿舍'})

        # 检查是否已有待处理的申请（不包括已退宿和已取消的申请）
        existing_application = conn.execute(
            "SELECT * FROM applications WHERE student_id = ? AND status IN ('pending', 'approved')",
            (user_id,)
        ).fetchone()

        if existing_application:
            conn.close()
            if existing_application['status'] == 'approved':
                app_logger.warning(f"申请失败: 已有批准的申请 - 用户ID={user_id}")
                return jsonify({'success': False, 'message': '您的宿舍申请已被批准，请先退宿再申请其他宿舍'})
            else:
                app_logger.warning(f"申请失败: 已有待处理的申请 - 用户ID={user_id}")
                return jsonify({'success': False, 'message': '您已有一个待处理的申请'})

        # 检查宿舍是否可申请
        dormitory = conn.execute(
            'SELECT * FROM dormitories WHERE id = ?',
            (dormitory_id,)
        ).fetchone()

        if not dormitory:
            conn.close()
            app_logger.warning(f"申请失败: 宿舍不存在 - 宿舍ID={dormitory_id}")
            return jsonify({'success': False, 'message': '宿舍不存在'})

        if dormitory['status'] != 'available':
            conn.close()
            app_logger.warning(f"申请失败: 宿舍不可用 - 宿舍ID={dormitory_id}, 状态={dormitory['status']}")
            return jsonify({'success': False, 'message': '该宿舍当前不可申请'})

        # 让数据库自动设置申请时间
        conn.execute(
            'INSERT INTO applications (student_id, dormitory_id) VALUES (?, ?)',
            (user_id, dormitory_id)
        )
        conn.commit()
        conn.close()

        # 记录审计日志
        user_info = f"ID: {user_id}, 姓名: {user_name}, 申请宿舍ID: {dormitory_id}"
        audit_logger.info("宿舍申请提交成功", extra={'user_info': user_info})

        app_logger.info(f"宿舍申请提交成功: 用户ID={user_id}, 宿舍ID={dormitory_id}")
        return jsonify({'success': True, 'message': '申请提交成功'})

    except Exception as e:
        app_logger.error(f"申请宿舍错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '申请失败'})


@app.route('/api/student/applications')
@login_required('student')
def get_student_applications():
    """获取学生申请记录"""
    try:
        user_id = session.get('user_id')
        app_logger.debug(f"获取申请记录: 用户ID={user_id}")

        conn = get_db_connection()
        applications = conn.execute('''
            SELECT a.*, d.building, d.room_number 
            FROM applications a 
            JOIN dormitories d ON a.dormitory_id = d.id 
            WHERE a.student_id = ?
            ORDER BY a.apply_date DESC
        ''', (user_id,)).fetchall()
        conn.close()

        result = []
        for app in applications:
            result.append({
                'id': app['id'],
                'building': app['building'],
                'room_number': app['room_number'],
                'status': app['status'],
                'apply_date': format_datetime(app['apply_date']),
                'processed_date': format_datetime(app['processed_date']),
                'admin_notes': app['admin_notes']
            })

        app_logger.debug(f"获取到 {len(result)} 条申请记录")
        return jsonify(result)

    except Exception as e:
        app_logger.error(f"获取申请记录错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify([])


@app.route('/api/student/announcements')
@login_required('student')
def get_announcements():
    """获取公告"""
    try:
        app_logger.debug("获取公告列表")

        conn = get_db_connection()
        announcements = conn.execute('''
            SELECT a.*, u.name as admin_name 
            FROM announcements a 
            JOIN users u ON a.admin_id = u.id 
            ORDER BY a.created_at DESC
        ''').fetchall()
        conn.close()

        result = []
        for ann in announcements:
            result.append({
                'id': ann['id'],
                'title': ann['title'],
                'content': ann['content'],
                'admin_name': ann['admin_name'],
                'created_at': format_datetime(ann['created_at'])
            })

        app_logger.debug(f"获取到 {len(result)} 条公告")
        return jsonify(result)

    except Exception as e:
        app_logger.error(f"获取公告错误: {str(e)}")
        return jsonify([])


@app.route('/api/student/feedback', methods=['GET', 'POST'])
@login_required('student')
def student_feedback():
    """学生反馈管理"""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()

        if request.method == 'GET':
            app_logger.debug(f"获取反馈记录: 用户ID={user_id}")

            feedbacks = conn.execute(
                'SELECT * FROM feedbacks WHERE student_id = ? ORDER BY created_at DESC',
                (user_id,)
            ).fetchall()
            conn.close()

            result = []
            for fb in feedbacks:
                result.append({
                    'id': fb['id'],
                    'title': fb['title'],
                    'content': fb['content'],
                    'status': fb['status'],
                    'created_at': format_datetime(fb['created_at']),
                    'resolved_at': format_datetime(fb['resolved_at']),
                    'admin_response': fb['admin_response'],
                    'category': fb['category']
                })

            app_logger.debug(f"获取到 {len(result)} 条反馈记录")
            return jsonify(result)

        else:
            data = request.json
            category = data.get('category', 'other')
            title = data.get('title')

            app_logger.info(f"提交反馈: 用户ID={user_id}, 标题={title}")

            # 让数据库自动设置创建时间
            conn.execute(
                'INSERT INTO feedbacks (student_id, title, content, category) VALUES (?, ?, ?, ?)',
                (user_id, title, data.get('content'), category)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {user_id}, 学号: {session.get('student_id')}"
            audit_logger.info(f"提交反馈: {title}", extra={'user_info': user_info})

            app_logger.info(f"反馈提交成功: 用户ID={user_id}, 标题={title}")
            return jsonify({'success': True, 'message': '反馈提交成功'})

    except Exception as e:
        app_logger.error(f"反馈处理错误: {str(e)}, 用户ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '操作失败'})


# 管理员功能
@app.route('/api/admin/dormitories', methods=['GET', 'POST'])
@login_required('admin')
def admin_dormitories():
    """管理员添加宿舍"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')
        conn = get_db_connection()

        if request.method == 'GET':
            app_logger.debug(f"管理员获取宿舍列表: 管理员ID={admin_id}")

            dormitories = conn.execute('SELECT * FROM dormitories ORDER BY building, room_number').fetchall()
            result = []
            for dorm in dormitories:
                result.append({
                    'id': dorm['id'],
                    'building': dorm['building'],
                    'room_number': dorm['room_number'],
                    'capacity': dorm['capacity'],
                    'current_occupancy': dorm['current_occupancy'],
                    'status': dorm['status'],
                    'description': dorm['description']
                })
            conn.close()

            app_logger.debug(f"管理员获取到 {len(result)} 个宿舍")
            return jsonify(result)

        else:
            data = request.json
            building = data.get('building')
            room_number = data.get('room_number')

            app_logger.info(f"管理员添加宿舍: 管理员ID={admin_id}, 宿舍={building}-{room_number}")

            # 检查宿舍是否已存在
            existing_dorm = conn.execute(
                'SELECT * FROM dormitories WHERE building = ? AND room_number = ?',
                (building, room_number)
            ).fetchone()

            if existing_dorm:
                conn.close()
                app_logger.warning(f"添加宿舍失败: 宿舍已存在 - {building}-{room_number}")
                return jsonify({'success': False, 'message': '宿舍已存在'})

            # 让数据库自动设置创建时间
            conn.execute(
                'INSERT INTO dormitories (building, room_number, capacity, description) VALUES (?, ?, ?, ?)',
                (building, room_number, data.get('capacity'), data.get('description'))
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            audit_logger.info(f"添加宿舍: {building}-{room_number}", extra={'user_info': user_info})

            app_logger.info(f"宿舍添加成功: {building}-{room_number}")
            return jsonify({'success': True, 'message': '宿舍添加成功'})

    except Exception as e:
        app_logger.error(f"宿舍管理错误: {str(e)}, 管理员ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '操作失败'})


@app.route('/api/admin/dormitories/<int:dorm_id>', methods=['DELETE'])
@login_required('admin')
def delete_dormitory(dorm_id):
    """删除宿舍"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')

        app_logger.info(f"删除宿舍请求: 管理员ID={admin_id}, 宿舍ID={dorm_id}")

        conn = get_db_connection()
        students_in_dorm = conn.execute(
            'SELECT COUNT(*) FROM users WHERE dormitory_id = ?', (dorm_id,)
        ).fetchone()[0]

        if students_in_dorm > 0:
            conn.close()
            app_logger.warning(f"删除宿舍失败: 宿舍有学生居住 - 宿舍ID={dorm_id}")
            return jsonify({'success': False, 'message': '该宿舍还有学生居住，无法删除'})

        pending_applications = conn.execute(
            'SELECT COUNT(*) FROM applications WHERE dormitory_id = ? AND status = "pending"', (dorm_id,)
        ).fetchone()[0]

        if pending_applications > 0:
            conn.close()
            app_logger.warning(f"删除宿舍失败: 有待处理的申请 - 宿舍ID={dorm_id}")
            return jsonify({'success': False, 'message': '该宿舍有待处理的申请，无法删除'})

        # 获取宿舍信息用于日志
        dorm = conn.execute('SELECT * FROM dormitories WHERE id = ?', (dorm_id,)).fetchone()

        conn.execute('DELETE FROM dormitories WHERE id = ?', (dorm_id,))
        conn.commit()
        conn.close()

        # 记录审计日志
        user_info = f"ID: {admin_id}, 姓名: {admin_name}"
        dorm_info = f"{dorm['building']}-{dorm['room_number']}" if dorm else f"ID:{dorm_id}"
        audit_logger.info(f"删除宿舍: {dorm_info}", extra={'user_info': user_info})

        app_logger.info(f"宿舍删除成功: 宿舍ID={dorm_id}")
        return jsonify({'success': True, 'message': '宿舍删除成功'})

    except Exception as e:
        app_logger.error(f"删除宿舍错误: {str(e)}, 管理员ID={session.get('user_id')}, 宿舍ID={dorm_id}")
        return jsonify({'success': False, 'message': '操作失败'})


@app.route('/api/admin/applications', methods=['GET', 'PUT'])
@login_required('admin')
def admin_applications():
    """管理员处理申请"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')
        conn = get_db_connection()

        if request.method == 'GET':
            app_logger.debug(f"管理员获取申请列表: 管理员ID={admin_id}")

            applications = conn.execute('''
                SELECT a.*, u.name as student_name, u.student_id as student_number, d.building, d.room_number 
                FROM applications a 
                JOIN users u ON a.student_id = u.id 
                JOIN dormitories d ON a.dormitory_id = d.id 
                WHERE a.status != 'cancelled'
                ORDER BY a.apply_date DESC
            ''').fetchall()
            conn.close()

            result = []
            for app in applications:
                result.append({
                    'id': app['id'],
                    'student_name': app['student_name'],
                    'student_id': app['student_number'],
                    'building': app['building'],
                    'room_number': app['room_number'],
                    'status': app['status'],
                    'apply_date': format_datetime(app['apply_date']),
                    'processed_date': format_datetime(app['processed_date']),
                    'admin_notes': app['admin_notes']
                })

            app_logger.debug(f"管理员获取到 {len(result)} 条申请记录")
            return jsonify(result)

        else:
            data = request.json
            app_id = data.get('id')
            status = data.get('status')
            admin_notes = data.get('admin_notes', '')

            app_logger.info(f"处理申请: 管理员ID={admin_id}, 申请ID={app_id}, 状态={status}")

            application = conn.execute(
                'SELECT * FROM applications WHERE id = ?', (app_id,)
            ).fetchone()

            if not application:
                conn.close()
                app_logger.warning(f"处理申请失败: 申请不存在 - 申请ID={app_id}")
                return jsonify({'success': False, 'message': '申请不存在'})

            # 检查申请状态
            if application['status'] != 'pending':
                conn.close()
                app_logger.warning(f"处理申请失败: 申请状态不可处理 - 申请ID={app_id}, 状态={application['status']}")
                return jsonify({'success': False, 'message': '该申请已处理，无法重复处理'})

            student_id = application['student_id']

            # 如果批准申请，检查学生是否已经有宿舍
            if status == 'approved':
                student = conn.execute(
                    'SELECT * FROM users WHERE id = ?', (student_id,)
                ).fetchone()

                if student and student['dormitory_id']:
                    conn.close()
                    app_logger.warning(f"处理申请失败: 学生已有宿舍 - 学生ID={student_id}")
                    return jsonify({'success': False, 'message': '该学生已经有宿舍了，请先退宿再分配新宿舍'})

            # 使用SQLite的datetime函数设置处理时间
            conn.execute(
                "UPDATE applications SET status = ?, admin_notes = ?, processed_date = datetime('now', 'localtime') WHERE id = ?",
                (status, admin_notes, app_id)
            )

            if status == 'approved':
                dormitory_id = application['dormitory_id']

                # 分配新宿舍
                conn.execute(
                    'UPDATE users SET dormitory_id = ? WHERE id = ?',
                    (dormitory_id, student_id)
                )

                # 更新宿舍入住人数
                dormitory = conn.execute(
                    'SELECT * FROM dormitories WHERE id = ?', (dormitory_id,)
                ).fetchone()

                new_occupancy = dormitory['current_occupancy'] + 1
                conn.execute(
                    'UPDATE dormitories SET current_occupancy = ? WHERE id = ?',
                    (new_occupancy, dormitory_id)
                )

                if new_occupancy >= dormitory['capacity']:
                    conn.execute(
                        'UPDATE dormitories SET status = "full" WHERE id = ?',
                        (dormitory_id,)
                    )

            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            action = "批准" if status == 'approved' else "拒绝" if status == 'rejected' else status
            audit_logger.info(f"处理申请: 申请ID={app_id}, 操作={action}", extra={'user_info': user_info})

            app_logger.info(f"申请处理成功: 申请ID={app_id}, 状态={status}")
            return jsonify({'success': True, 'message': '申请处理成功'})

    except Exception as e:
        app_logger.error(f"处理申请错误: {str(e)}, 管理员ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '操作失败'})


@app.route('/api/admin/announcements', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required('admin')
def admin_announcements():
    """管理员公告管理"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')
        conn = get_db_connection()

        if request.method == 'GET':
            app_logger.debug(f"管理员获取公告列表: 管理员ID={admin_id}")

            announcements = conn.execute('''
                SELECT a.*, u.name as admin_name 
                FROM announcements a 
                JOIN users u ON a.admin_id = u.id 
                ORDER BY a.created_at DESC
            ''').fetchall()
            conn.close()

            result = []
            for ann in announcements:
                result.append({
                    'id': ann['id'],
                    'title': ann['title'],
                    'content': ann['content'],
                    'admin_name': ann['admin_name'],
                    'created_at': format_datetime(ann['created_at'])
                })

            app_logger.debug(f"管理员获取到 {len(result)} 条公告")
            return jsonify(result)

        elif request.method == 'POST':
            data = request.json
            title = data.get('title')

            app_logger.info(f"发布公告: 管理员ID={admin_id}, 标题={title}")

            # 让数据库自动设置创建时间
            conn.execute(
                'INSERT INTO announcements (title, content, admin_id) VALUES (?, ?, ?)',
                (title, data.get('content'), admin_id)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            audit_logger.info(f"发布公告: {title}", extra={'user_info': user_info})

            app_logger.info(f"公告发布成功: 标题={title}")
            return jsonify({'success': True, 'message': '公告发布成功'})

        elif request.method == 'PUT':
            data = request.json
            ann_id = data.get('id')
            title = data.get('title')

            app_logger.info(f"更新公告: 管理员ID={admin_id}, 公告ID={ann_id}")

            conn.execute(
                'UPDATE announcements SET title = ?, content = ? WHERE id = ?',
                (title, data.get('content'), ann_id)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            audit_logger.info(f"更新公告: ID={ann_id}, 标题={title}", extra={'user_info': user_info})

            app_logger.info(f"公告更新成功: 公告ID={ann_id}")
            return jsonify({'success': True, 'message': '公告更新成功'})

        else:
            ann_id = request.args.get('id')
            app_logger.info(f"删除公告: 管理员ID={admin_id}, 公告ID={ann_id}")

            # 获取公告信息用于日志
            announcement = conn.execute(
                'SELECT title FROM announcements WHERE id = ?', (ann_id,)
            ).fetchone()

            conn.execute('DELETE FROM announcements WHERE id = ?', (ann_id,))
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            title = announcement['title'] if announcement else '未知标题'
            audit_logger.info(f"删除公告: {title} (ID={ann_id})", extra={'user_info': user_info})

            app_logger.info(f"公告删除成功: 公告ID={ann_id}")
            return jsonify({'success': True, 'message': '公告删除成功'})

    except Exception as e:
        app_logger.error(f"公告管理错误: {str(e)}, 管理员ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '操作失败'})


@app.route('/api/admin/feedbacks', methods=['GET', 'PUT'])
@login_required('admin')
def admin_feedbacks():
    """管理员反馈管理"""
    try:
        admin_id = session.get('user_id')
        admin_name = session.get('name')
        conn = get_db_connection()

        if request.method == 'GET':
            app_logger.debug(f"管理员获取反馈列表: 管理员ID={admin_id}")

            feedbacks = conn.execute('''
                SELECT f.*, u.name as student_name, u.student_id as student_number 
                FROM feedbacks f 
                JOIN users u ON f.student_id = u.id 
                ORDER BY f.created_at DESC
            ''').fetchall()
            conn.close()

            result = []
            for fb in feedbacks:
                result.append({
                    'id': fb['id'],
                    'student_name': fb['student_name'],
                    'student_id': fb['student_number'],
                    'title': fb['title'],
                    'content': fb['content'],
                    'status': fb['status'],
                    'created_at': format_datetime(fb['created_at']),
                    'resolved_at': format_datetime(fb['resolved_at']),
                    'admin_response': fb['admin_response'],
                    'category': fb['category']
                })

            app_logger.debug(f"管理员获取到 {len(result)} 条反馈记录")
            return jsonify(result)

        else:
            data = request.json
            fb_id = data.get('id')
            admin_response = data.get('admin_response')

            app_logger.info(f"处理反馈: 管理员ID={admin_id}, 反馈ID={fb_id}")

            # 使用SQLite的datetime函数设置处理时间
            conn.execute(
                "UPDATE feedbacks SET status = 'resolved', admin_response = ?, resolved_at = datetime('now', 'localtime') WHERE id = ?",
                (admin_response, fb_id)
            )
            conn.commit()
            conn.close()

            # 记录审计日志
            user_info = f"ID: {admin_id}, 姓名: {admin_name}"
            audit_logger.info(f"处理反馈: 反馈ID={fb_id}", extra={'user_info': user_info})

            app_logger.info(f"反馈已处理: 反馈ID={fb_id}")
            return jsonify({'success': True, 'message': '反馈已处理'})

    except Exception as e:
        app_logger.error(f"反馈管理错误: {str(e)}, 管理员ID={session.get('user_id')}")
        return jsonify({'success': False, 'message': '操作失败'})


# 获取宿舍内学生信息
@app.route('/api/admin/dormitories/<int:dorm_id>/students')
@login_required('admin')
def get_dormitory_students(dorm_id):
    """获取宿舍内的学生信息"""
    try:
        admin_id = session.get('user_id')
        app_logger.info(f"查看宿舍学生信息: 管理员ID={admin_id}, 宿舍ID={dorm_id}")

        conn = get_db_connection()

        # 获取宿舍基本信息
        dormitory = conn.execute(
            'SELECT * FROM dormitories WHERE id = ?',
            (dorm_id,)
        ).fetchone()

        if not dormitory:
            conn.close()
            app_logger.warning(f"宿舍不存在: 宿舍ID={dorm_id}")
            return jsonify({'success': False, 'message': '宿舍不存在'})

        # 获取宿舍内的学生信息
        students = conn.execute('''
            SELECT u.id, u.name, u.student_id, u.gender, u.age, u.major, u.phone, u.created_at
            FROM users u 
            WHERE u.dormitory_id = ? AND u.role = 'student'
            ORDER BY u.student_id
        ''', (dorm_id,)).fetchall()

        conn.close()

        # 格式化返回数据
        dorm_info = {
            'id': dormitory['id'],
            'building': dormitory['building'],
            'room_number': dormitory['room_number'],
            'capacity': dormitory['capacity'],
            'current_occupancy': dormitory['current_occupancy'],
            'status': dormitory['status']
        }

        students_list = []
        for student in students:
            students_list.append({
                'id': student['id'],
                'name': student['name'],
                'student_id': student['student_id'],
                'gender': student['gender'],
                'age': student['age'],
                'major': student['major'],
                'phone': student['phone'],
                'joined_date': format_datetime(student['created_at'])
            })

        app_logger.info(f"获取宿舍学生信息成功: 宿舍ID={dorm_id}, 学生数={len(students_list)}")
        return jsonify({
            'success': True,
            'dormitory': dorm_info,
            'students': students_list
        })

    except Exception as e:
        app_logger.error(f"获取宿舍学生信息错误: {str(e)}, 宿舍ID={dorm_id}")
        return jsonify({'success': False, 'message': '获取信息失败'})


# 统计信息
@app.route('/api/admin/stats')
@login_required('admin')
def admin_stats():
    """获取统计信息"""
    try:
        admin_id = session.get('user_id')
        app_logger.debug(f"获取统计信息: 管理员ID={admin_id}")

        conn = get_db_connection()
        total_students = conn.execute('SELECT COUNT(*) FROM users WHERE role = "student"').fetchone()[0]
        total_dorms = conn.execute('SELECT COUNT(*) FROM dormitories').fetchone()[0]
        pending_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "pending"').fetchone()[0]
        pending_feedbacks = conn.execute('SELECT COUNT(*) FROM feedbacks WHERE status = "pending"').fetchone()[0]

        conn.close()

        app_logger.debug(
            f"统计信息: 学生数={total_students}, 宿舍数={total_dorms}, 待处理申请={pending_applications}, 待处理反馈={pending_feedbacks}")

        return jsonify({
            'total_students': total_students,
            'total_dorms': total_dorms,
            'pending_applications': pending_applications,
            'pending_feedbacks': pending_feedbacks
        })

    except Exception as e:
        app_logger.error(f"获取统计信息错误: {str(e)}")
        return jsonify({
            'total_students': 0,
            'total_dorms': 0,
            'pending_applications': 0,
            'pending_feedbacks': 0
        })


# 健康检查
@app.route('/api/health')
def health_check():
    """系统健康检查"""
    try:
        # 检查数据库连接
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()

        app_logger.debug("健康检查: 系统运行正常")
        return jsonify({'status': 'healthy', 'message': '系统运行正常'})

    except Exception as e:
        app_logger.error(f"健康检查失败: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'message': '系统异常',
            'error': str(e)
        }), 500


# 日志查看API
@app.route('/api/admin/logs', methods=['GET'])
@login_required('admin')
def get_logs():
    """获取系统日志"""
    try:
        admin_id = session.get('user_id')
        app_logger.info(f"管理员查看日志: 管理员ID={admin_id}")

        # 读取最近的日志文件内容
        logs = []
        log_files = {
            'app.log': '应用日志',
            'error.log': '错误日志',
            'audit.log': '审计日志'
        }

        for filename, description in log_files.items():
            filepath = os.path.join('logs', filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # 获取最后100行
                        lines = content.strip().split('\n')
                        recent_lines = lines[-100:] if len(lines) > 100 else lines
                        logs.append({
                            'filename': filename,
                            'description': description,
                            'lines': len(lines),
                            'recent_logs': recent_lines[-20:]  # 返回最近20行
                        })
                except Exception as e:
                    app_logger.error(f"读取日志文件失败: {filename}, 错误: {str(e)}")

        return jsonify({
            'success': True,
            'logs': logs
        })

    except Exception as e:
        app_logger.error(f"获取日志失败: {str(e)}")
        return jsonify({'success': False, 'message': '获取日志失败'})


if __name__ == '__main__':
    # 检查数据库是否存在，不存在则初始化
    if not os.path.exists(DATABASE):
        app_logger.info("数据库不存在，正在初始化...")
        init_db_simple()

    # 检查是否存在static文件夹，如果不存在则创建
    if not os.path.exists('static'):
        os.makedirs('static')
        app_logger.info("创建static文件夹")

    # 记录审计日志
    audit_logger.info("系统启动", extra={'user_info': '系统'})

    app.run(debug=True, host='127.0.0.1', port=5000)