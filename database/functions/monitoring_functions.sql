CREATE FUNCTION start_user_network_trace(
    p_user_id BIGINT,
    p_challenge_template_id BIGINT
)
    RETURNS SETOF INTEGER AS $$
DECLARE
    v_username TEXT;
    v_email TEXT;
    v_challenge_id BIGINT;
    v_trace_id INTEGER;
    v_subnet INET;
BEGIN
    -- Get username + email from users
    SELECT u1.username, u1.email
    INTO v_username, v_email
    FROM users u1
    WHERE u1.id = p_user_id;

    IF v_username IS NULL THEN
        RAISE EXCEPTION 'User with ID % not found', p_user_id;
    END IF;

    -- Find the most recent challenge instance for this template
    SELECT u2.id INTO v_challenge_id
    FROM users u2 JOIN challenges c ON u2.running_challenge = c.id
    WHERE c.challenge_template_id = p_challenge_template_id;

    IF v_challenge_id IS NULL THEN
        RAISE EXCEPTION 'No challenge instance found for template %', p_challenge_template_id;
    END IF;

    -- Loop through all subnets linked to that challenge
    FOR v_subnet IN
        SELECT n.subnet
        FROM networks n
        WHERE n.challenge_id = v_challenge_id
        LOOP
            INSERT INTO user_network_trace (username, email, subnet)
            VALUES (v_username, v_email, v_subnet)
            RETURNING id INTO v_trace_id;

            RAISE NOTICE 'Started trace for user % on subnet % (trace id = %)',
                v_username, v_subnet, v_trace_id;

            RETURN NEXT v_trace_id;
        END LOOP;

    RETURN;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION stop_user_network_trace(
    p_user_id BIGINT,
    p_challenge_template_id BIGINT
)
    RETURNS VOID AS $$
DECLARE
    v_username TEXT;
    v_challenge_id BIGINT;
    v_count INT;
BEGIN
    -- Get username
    SELECT u1.username INTO v_username FROM users u1 WHERE u1.id = p_user_id;
    IF v_username IS NULL THEN
        RAISE EXCEPTION 'User with ID % not found', p_user_id;
    END IF;

    -- Find the challenge instance
    SELECT u2.id INTO v_challenge_id
    FROM users u2 JOIN challenges c ON u2.running_challenge = c.id
    WHERE c.challenge_template_id = p_challenge_template_id;

    IF v_challenge_id IS NULL THEN
        RAISE EXCEPTION 'No challenge instance found for template %', p_challenge_template_id;
    END IF;

    -- Stop all active traces for all networks linked to that challenge
    WITH updated AS (
        UPDATE user_network_trace ut
        SET stopped_at = NOW()
        WHERE ut.username = v_username
          AND ut.stopped_at IS NULL
          AND ut.subnet IN (
            SELECT subnet FROM networks n WHERE n.challenge_id = v_challenge_id
        )
        RETURNING 1
    )
    SELECT COUNT(*) INTO v_count FROM updated;

    IF v_count = 0 THEN
        RAISE NOTICE 'No active traces found for user % on challenge %', v_username, v_challenge_id;
    ELSE
        RAISE NOTICE 'Stopped % trace(s) for user % on challenge %', v_count, v_username, v_challenge_id;
    END IF;
END;
$$ LANGUAGE plpgsql;