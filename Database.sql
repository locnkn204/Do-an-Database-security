--------------------------------------------------------
-- 1. TẠO PROFILE
--------------------------------------------------------
CREATE PROFILE APP_USER_PROFILE LIMIT
    SESSIONS_PER_USER 2          -- Giới hạn 2 thiết bị
    FAILED_LOGIN_ATTEMPTS 3      -- Sai 3 lần thì khóa
    PASSWORD_LOCK_TIME 30/1440   -- Khóa trong 30 phút
    IDLE_TIME 15;                -- Treo máy 15 phút tự out

--------------------------------------------------------
-- 2. TẠO BẢNG (TABLES)
--------------------------------------------------------
CREATE TABLE USERS (
    ID NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    USERNAME VARCHAR2(50) UNIQUE NOT NULL,
    PASSWORD_HASH VARCHAR2(255) NOT NULL,
    EMAIL VARCHAR2(100) UNIQUE NOT NULL,
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FAILED_ATTEMPTS NUMBER DEFAULT 0,
    ACCOUNT_LOCKED NUMBER(1) DEFAULT 0,
    LOCKED_UNTIL TIMESTAMP
);

CREATE TABLE SESSIONS (
    ID NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    USER_ID NUMBER NOT NULL,
    TOKEN VARCHAR2(255) NOT NULL,
    CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ACTIVE NUMBER(1) DEFAULT 1,
    LAST_ACTIVITY TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    EXPIRE_AT TIMESTAMP,
    CONSTRAINT FK_SESSION_USER FOREIGN KEY (USER_ID) REFERENCES USERS(ID)
);

CREATE TABLE PROFILES (
    USER_ID NUMBER PRIMARY KEY,
    FULL_NAME VARCHAR2(100),
    BIO VARCHAR2(500),
    UPDATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT FK_PROFILE_USER FOREIGN KEY (USER_ID) REFERENCES USERS(ID)
);

CREATE TABLE LOGS (
    ID NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    USER_ID NUMBER,
    ACTION VARCHAR2(100) NOT NULL,
    TIMESTAMP TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT FK_LOG_USER FOREIGN KEY (USER_ID) REFERENCES USERS(ID)
);

CREATE TABLE LOGIN_ATTEMPTS (
    ID NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    USER_ID NUMBER NOT NULL,
    ATTEMPT_TIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    SUCCESS NUMBER(1),
    CONSTRAINT FK_ATTEMPT_USER FOREIGN KEY (USER_ID) REFERENCES USERS(ID)
);


CREATE TABLE USER_SECURITY_POLICY (
    USER_ID NUMBER PRIMARY KEY,
    MAX_SESSION_TIME NUMBER DEFAULT 120,
    MAX_IDLE_TIME NUMBER DEFAULT 5,
    MAX_FAILED_LOGIN NUMBER DEFAULT 3,
    LOCK_DURATION NUMBER DEFAULT 30,
    CONSTRAINT FK_POLICY_USER FOREIGN KEY (USER_ID) REFERENCES USERS(ID)
);

CREATE TABLE secure_files (
    id NUMBER GENERATED ALWAYS AS IDENTITY,
    username VARCHAR2(50),
    filename VARCHAR2(255),
    data_enc BLOB,
    created_at DATE DEFAULT SYSDATE
);

--------------------------------------------------------
-- 3. INSERT DỮ LIỆU MẪU
--------------------------------------------------------
INSERT INTO USERS (USERNAME, PASSWORD_HASH, EMAIL)
VALUES ('binh', 'hash_demo_123', 'binh@email.com');

INSERT INTO PROFILES (USER_ID, FULL_NAME, BIO)
SELECT ID, 'Nguyen Van Binh', 'Demo user' FROM USERS WHERE USERNAME = 'binh';

INSERT INTO USER_SECURITY_POLICY (USER_ID)
SELECT ID FROM USERS WHERE USERNAME = 'binh';

COMMIT;

--------------------------------------------------------
-- 4. HÀM MÃ HÓA DES
--------------------------------------------------------
CREATE OR REPLACE FUNCTION des_encrypt_raw(
    p_data IN RAW,
    p_key  IN RAW
) RETURN RAW
IS
    encrypted RAW(32767);
BEGIN
    encrypted := DBMS_CRYPTO.encrypt(
        src => p_data,
        typ => DBMS_CRYPTO.encrypt_des + DBMS_CRYPTO.chain_cbc + DBMS_CRYPTO.pad_pkcs5,
        key => p_key
    );
    RETURN encrypted;
END;
/

CREATE OR REPLACE FUNCTION des_decrypt_raw(
    p_data IN RAW,
    p_key  IN RAW
) RETURN RAW
IS
    decrypted RAW(32767);
BEGIN
    decrypted := DBMS_CRYPTO.decrypt(
        src => p_data,
        typ => DBMS_CRYPTO.encrypt_des + DBMS_CRYPTO.chain_cbc + DBMS_CRYPTO.pad_pkcs5,
        key => p_key
    );
    RETURN decrypted;
END;
/

--------------------------------------------------------
-- 5. CÁC THỦ TỤC
--------------------------------------------------------

-- Thủ tục cấp/thu hồi quyền
CREATE OR REPLACE PROCEDURE grant_table_priv(
    p_user      IN VARCHAR2,
    p_table     IN VARCHAR2,
    p_privilege IN VARCHAR2
) AS
    sql_stmt VARCHAR2(4000);
BEGIN
    sql_stmt := 'GRANT ' || p_privilege || ' ON ' || p_table || ' TO ' || p_user;
    EXECUTE IMMEDIATE sql_stmt;
END;
/

CREATE OR REPLACE PROCEDURE revoke_table_priv(
    p_user      IN VARCHAR2,
    p_table     IN VARCHAR2,
    p_privilege IN VARCHAR2
) AS
    sql_stmt VARCHAR2(4000);
BEGIN
    sql_stmt := 'REVOKE ' || p_privilege || ' ON ' || p_table || ' FROM ' || p_user;
    EXECUTE IMMEDIATE sql_stmt;
END;
/

-- Thủ tục thêm user vào bảng theo dõi (App gọi khi đăng ký user mới)
CREATE OR REPLACE PROCEDURE add_user_to_tracking(
    p_username IN VARCHAR2,
    p_password_hash IN VARCHAR2,
    p_email IN VARCHAR2 DEFAULT NULL,
    p_status OUT VARCHAR2
) IS
    v_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_count FROM USERS WHERE USERNAME = p_username;
    IF v_count > 0 THEN
        p_status := 'USER_EXISTS';
        RETURN;
    END IF;
    
    INSERT INTO USERS (USERNAME, PASSWORD_HASH, EMAIL)
    VALUES (p_username, p_password_hash, p_email);
    
    COMMIT;
    p_status := 'SUCCESS';
EXCEPTION
    WHEN OTHERS THEN
        p_status := 'ERROR: ' || SQLERRM;
        ROLLBACK;
END add_user_to_tracking;
/

-- Thủ tục ghi log đăng nhập (App gọi khi user đăng nhập)
CREATE OR REPLACE PROCEDURE record_login_attempt_proc(
    p_username IN VARCHAR2,
    p_success IN NUMBER,
    p_status OUT VARCHAR2
) IS
    v_user_id NUMBER;
BEGIN
    SELECT ID INTO v_user_id FROM USERS WHERE USERNAME = p_username;
    
    INSERT INTO LOGIN_ATTEMPTS (USER_ID, SUCCESS)
    VALUES (v_user_id, p_success);
    
    COMMIT;
    p_status := 'SUCCESS';
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        p_status := 'USER_NOT_FOUND';
    WHEN OTHERS THEN
        p_status := 'ERROR: ' || SQLERRM;
        ROLLBACK;
END record_login_attempt_proc;
/

-- Thủ tục Add data generic (App gọi để thêm dữ liệu)
CREATE OR REPLACE PROCEDURE insert_record_generic(
    p_table_name IN VARCHAR2,
    p_col1 IN VARCHAR2 DEFAULT NULL, p_val1 IN VARCHAR2 DEFAULT NULL,
    p_col2 IN VARCHAR2 DEFAULT NULL, p_val2 IN VARCHAR2 DEFAULT NULL,
    p_col3 IN VARCHAR2 DEFAULT NULL, p_val3 IN VARCHAR2 DEFAULT NULL,
    p_col4 IN VARCHAR2 DEFAULT NULL, p_val4 IN VARCHAR2 DEFAULT NULL,
    p_col5 IN VARCHAR2 DEFAULT NULL, p_val5 IN VARCHAR2 DEFAULT NULL,
    p_col6 IN VARCHAR2 DEFAULT NULL, p_val6 IN VARCHAR2 DEFAULT NULL,
    p_col7 IN VARCHAR2 DEFAULT NULL, p_val7 IN VARCHAR2 DEFAULT NULL,
    p_col8 IN VARCHAR2 DEFAULT NULL, p_val8 IN VARCHAR2 DEFAULT NULL,
    p_col9 IN VARCHAR2 DEFAULT NULL, p_val9 IN VARCHAR2 DEFAULT NULL,
    p_col10 IN VARCHAR2 DEFAULT NULL, p_val10 IN VARCHAR2 DEFAULT NULL,
    p_status OUT VARCHAR2
) IS
    v_sql VARCHAR2(4000);
    v_cols VARCHAR2(2000);
    v_vals VARCHAR2(2000);
    v_count NUMBER := 0;
BEGIN
    IF p_col1 IS NOT NULL THEN v_cols := p_col1; v_vals := ':1'; v_count := v_count + 1; END IF;
    IF p_col2 IS NOT NULL THEN v_cols := v_cols || ', ' || p_col2; v_vals := v_vals || ', :2'; v_count := v_count + 1; END IF;
    IF p_col3 IS NOT NULL THEN v_cols := v_cols || ', ' || p_col3; v_vals := v_vals || ', :3'; v_count := v_count + 1; END IF;
    IF p_col4 IS NOT NULL THEN v_cols := v_cols || ', ' || p_col4; v_vals := v_vals || ', :4'; v_count := v_count + 1; END IF;
    IF p_col5 IS NOT NULL THEN v_cols := v_cols || ', ' || p_col5; v_vals := v_vals || ', :5'; v_count := v_count + 1; END IF;
    
    IF v_count = 0 THEN p_status := 'ERROR: Không có cột'; RETURN; END IF;
    
    v_sql := 'INSERT INTO ' || p_table_name || ' (' || v_cols || ') VALUES (' || v_vals || ')';
    
    BEGIN
        IF v_count = 1 THEN EXECUTE IMMEDIATE v_sql USING p_val1;
        ELSIF v_count = 2 THEN EXECUTE IMMEDIATE v_sql USING p_val1, p_val2;
        ELSIF v_count = 3 THEN EXECUTE IMMEDIATE v_sql USING p_val1, p_val2, p_val3;
        ELSIF v_count = 4 THEN EXECUTE IMMEDIATE v_sql USING p_val1, p_val2, p_val3, p_val4;
        ELSIF v_count = 5 THEN EXECUTE IMMEDIATE v_sql USING p_val1, p_val2, p_val3, p_val4, p_val5;
        END IF;
        COMMIT;
        p_status := 'SUCCESS: Inserted';
    EXCEPTION WHEN OTHERS THEN
        ROLLBACK;
        p_status := 'ERROR: ' || SQLERRM;
    END;
END;
/

--------------------------------------------------------
-- 6. Mãhóa RSA 
--------------------------------------------------------
--- Tạo khóa
CREATE OR REPLACE PROCEDURE GENERATE_RSA_KEYS (
    p_public_key  OUT CLOB,
    p_private_key OUT CLOB
) AS
    v_key_pair  BLOB;
BEGIN
    -- Tạo cặp khóa RSA 2048 bit
    v_key_pair := DBMS_CRYPTO.KEYGEN(
        key_type => DBMS_CRYPTO.KEY_TYPE_RSA,
        key_len  => 2048
    );

    -- Tách lấy Public Key 
    p_public_key := REGEXP_SUBSTR(
        UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(v_key_pair)),
        '-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----',
        1, 1, 'n'
    );

    -- Tách lấy Private Key 
    p_private_key := REGEXP_SUBSTR(
        UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(v_key_pair)),
        '-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
        1, 1, 'n'
    );

    IF p_public_key IS NULL THEN
        p_private_key := UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(v_key_pair));
        p_public_key := p_private_key; 
    END IF;
END;
/

--- Mã hóa
CREATE OR REPLACE PROCEDURE RSA_ENCRYPT (
    p_plaintext   IN  VARCHAR2, -- Dữ liệu cần mã hóa
    p_public_key  IN  CLOB,     -- Key dùng để mã hóa (dạng Base64 hoặc RAW text)
    p_encrypted   OUT VARCHAR2  -- Kết quả trả về
) AS
    v_src_raw     RAW(32767);
    v_pub_key_raw RAW(32767);
    v_enc_raw     RAW(32767);
BEGIN
    -- 1. Chuyển chuỗi cần mã hóa sang dạng RAW
    v_src_raw := UTL_I18N.STRING_TO_RAW(p_plaintext, 'AL32UTF8');

    -- 2. Chuyển Public Key từ String (Base64) 
    v_pub_key_raw := UTL_ENCODE.BASE64_DECODE(UTL_RAW.CAST_TO_RAW(p_public_key));

    -- 3. Thực hiện mã hóa RSA
    v_enc_raw := DBMS_CRYPTO.ENCRYPT(
        src => v_src_raw,
        typ => DBMS_CRYPTO.ENCRYPT_RSA_PKCS1_OAEP_SHA1, -- Chuẩn padding an toàn
        key => v_pub_key_raw
    );

    -- 4. Chuyển kết quả mã hóa sang Base64 để trả về App 
    p_encrypted := UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(v_enc_raw));

EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Lỗi mã hóa: ' || SQLERRM);
        RAISE;
END;
/
---- Giải mã
CREATE OR REPLACE PROCEDURE RSA_DECRYPT (
    p_encrypted_data IN  VARCHAR2, -- Dữ liệu đã mã hóa (dạng Base64)
    p_private_key    IN  CLOB,     -- Private Key
    p_decrypted      OUT VARCHAR2  -- Kết quả giải mã
) AS
    v_enc_raw      RAW(32767);
    v_priv_key_raw RAW(32767);
    v_dec_raw      RAW(32767);
BEGIN
    -- 1. Chuyển dữ liệu mã hóa từ Base64 về RAW
    v_enc_raw := UTL_ENCODE.BASE64_DECODE(UTL_RAW.CAST_TO_RAW(p_encrypted_data));

    -- 2. Chuyển Private Key về RAW
    v_priv_key_raw := UTL_ENCODE.BASE64_DECODE(UTL_RAW.CAST_TO_RAW(p_private_key));

    -- 3. Thực hiện giải mã
    v_dec_raw := DBMS_CRYPTO.DECRYPT(
        src => v_enc_raw,
        typ => DBMS_CRYPTO.ENCRYPT_RSA_PKCS1_OAEP_SHA1,
        key => v_priv_key_raw
    );

    -- 4. Chuyển về dạng chuỗi đọc được
    p_decrypted := UTL_I18N.RAW_TO_CHAR(v_dec_raw, 'AL32UTF8');

EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Lỗi giải mã: ' || SQLERRM);
        RAISE; 
END;
/