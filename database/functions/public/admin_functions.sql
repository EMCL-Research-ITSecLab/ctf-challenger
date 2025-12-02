#CREATE FUNCTION reset_user_password(
    p_user_id BIGINT,
    p_cleartext_password TEXT
)
    RETURNS TEXT
    LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
DECLARE
v_new_salt TEXT;
    v_new_password_hash TEXT;
BEGIN
    v_new_salt := encode(gen_random_bytes(16), 'hex');
    v_new_password_hash := encode(digest(v_new_salt || p_cleartext_password, 'sha512'), 'hex');

UPDATE users
SET password_hash = v_new_password_hash,
    password_salt = v_new_salt,
    password_reset = TRUE,
    password_reset_timestamp = CURRENT_TIMESTAMP
WHERE id = p_user_id;

IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found';
END IF;
RETURN p_cleartext_password;
END;
$$;