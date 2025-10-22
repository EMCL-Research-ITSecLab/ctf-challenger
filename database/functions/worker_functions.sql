CREATE FUNCTION get_expired_challenge_data()
RETURNS TABLE (
    user_id BIGINT,
    username TEXT,
    challenge_id BIGINT,
    challenge_template_id BIGINT,
    expires_at TIMESTAMP
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.id::BIGINT AS user_id,
        u.username::TEXT AS username,
        c.id::BIGINT AS challenge_id,
        c.challenge_template_id::BIGINT AS challenge_template_id,
        c.expires_at::TIMESTAMP AS expires_at
    FROM users u
    JOIN challenges c ON u.running_challenge = c.id
    WHERE c.expires_at <= CURRENT_TIMESTAMP;
END;
$$;
