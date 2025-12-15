import sqlite3

# 连接到数据库
conn = sqlite3.connect('dormitory.db')

# 创建一个游标对象
cursor = conn.cursor()

# 执行SQL语句
cursor.execute("SELECT * FROM users")

# 获取查询结果
result = cursor.fetchall()

# 输出结果
for row in result:
    print(row)

# 关闭游标和数据库连接
cursor.close()
conn.close()