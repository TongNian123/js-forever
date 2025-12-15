import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

# 创建日志目录
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 日志格式
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def setup_logger():
    """配置日志系统"""

    # 创建根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # 清除现有的处理器
    root_logger.handlers = []

    # 1. 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)

    # 2. 应用日志文件处理器
    app_handler = RotatingFileHandler(
        filename=os.path.join(log_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    app_handler.setLevel(logging.INFO)
    app_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    app_handler.setFormatter(app_formatter)

    # 3. 错误日志文件处理器
    error_handler = RotatingFileHandler(
        filename=os.path.join(log_dir, 'error.log'),
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    error_handler.setFormatter(error_formatter)

    # 4. 审计日志文件处理器
    audit_handler = RotatingFileHandler(
        filename=os.path.join(log_dir, 'audit.log'),
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5,
        encoding='utf-8'
    )
    audit_handler.setLevel(logging.INFO)
    audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [User: %(user_info)s] - %(message)s')
    audit_handler.setFormatter(audit_formatter)

    # 将处理器添加到根日志记录器
    root_logger.addHandler(console_handler)
    root_logger.addHandler(app_handler)
    root_logger.addHandler(error_handler)

    # 创建审计日志记录器
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False

    return {
        'app': root_logger,
        'audit': audit_logger
    }


# 初始化日志记录器
loggers = setup_logger()
app_logger = loggers['app']
audit_logger = loggers['audit']