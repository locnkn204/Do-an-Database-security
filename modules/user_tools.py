def delete_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"DROP USER {username.upper()} CASCADE")
    conn.commit()