import cx_Oracle

def oracle_des_encrypt_file(conn, input_path, output_path):
    data = open(input_path, "rb").read()
    cur = conn.cursor()

    cur.execute("""
        SELECT des_encrypt_raw(:data) FROM dual
    """, data=data)

    encrypted, = cur.fetchone()
    open(output_path, "wb").write(encrypted)

    cur.close()


def oracle_des_decrypt_file(conn, input_path, output_path):
    data = open(input_path, "rb").read()
    cur = conn.cursor()

    cur.execute("""
        SELECT des_decrypt_raw(:data) FROM dual
    """, data=data)

    decrypted, = cur.fetchone()
    open(output_path, "wb").write(decrypted)

    cur.close()