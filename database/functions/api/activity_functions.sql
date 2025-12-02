CREATE FUNCTION get_user_activities(
    p_user_id BIGINT,
    p_challenge_category challenge_category,
    p_type_filter TEXT,
    p_date_range TEXT,
    p_limit BIGINT,
    p_offset BIGINT
)
RETURNS TABLE (
    activity_type TEXT,
    item_id BIGINT,
    item_name TEXT,
    category challenge_category,
    points BIGINT,
    solved BOOLEAN,
    attempt_number BIGINT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT,
    activity_date TIMESTAMP,
    icon TEXT,
    color badge_color,
    description TEXT,
    item_type TEXT,
    flag_id BIGINT
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
DECLARE
    v_date_start TIMESTAMP;
BEGIN
    IF p_date_range = 'today' THEN
        v_date_start := CURRENT_TIMESTAMP - INTERVAL '1 day';
    ELSIF p_date_range = 'week' THEN
        v_date_start := CURRENT_TIMESTAMP - INTERVAL '1 week';
    ELSIF p_date_range = 'month' THEN
        v_date_start := CURRENT_TIMESTAMP - INTERVAL '1 month';
    ELSIF p_date_range = 'year' THEN
        v_date_start := CURRENT_TIMESTAMP - INTERVAL '1 year';
    ELSE
        v_date_start := NULL;
    END IF;

    RETURN QUERY
    SELECT
        co.activity_type,
        co.item_id,
        co.item_name,
        co.category,
        co.points,
        co.solved,
        co.attempt_number,
        co.started_at,
        co.completed_at,
        co.status,
        co.activity_date,
        co.icon,
        co.color,
        co.description,
        co.item_type,
        co.flag_id
    FROM (
        (
            WITH flag_counts AS (
                SELECT
                    challenge_template_id,
                    COUNT(id) AS total_flags
                FROM challenge_flags
                GROUP BY challenge_template_id
            ),
            user_flag_submissions AS (
                SELECT
                    cc.challenge_template_id,
                    cc.id AS completion_id,
                    cc.flag_id,
                    cc.completed_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY cc.challenge_template_id
                        ORDER BY cc.completed_at DESC
                    ) AS submission_rank,
                    COUNT(cf.id) OVER (
                        PARTITION BY cc.challenge_template_id
                    ) AS user_submitted_flags
                FROM completed_challenges cc
                JOIN challenge_flags cf ON cc.flag_id = cf.id
                WHERE cc.user_id = p_user_id
            ),
            challenge_attempts AS (
                SELECT
                    cc.id,
                    cc.challenge_template_id,
                    cc.started_at,
                    cc.completed_at,
                    cc.flag_id,
                    ct.name,
                    ct.category,
                    cf.points,
                    ROW_NUMBER() OVER (
                        PARTITION BY cc.challenge_template_id
                        ORDER BY cc.started_at
                    ) AS attempt_number,
                    CASE
                        WHEN ufs.submission_rank = 1 AND ufs.user_submitted_flags = fc.total_flags THEN 'solved'
                        WHEN cc.flag_id IS NOT NULL THEN 'flag_submitted'
                        WHEN cc.completed_at IS NOT NULL AND cc.flag_id IS NULL THEN 'failed'
                        ELSE 'active'
                    END AS status,
                    CASE
                        WHEN cc.completed_at IS NOT NULL THEN cc.completed_at
                        ELSE cc.started_at
                    END AS activity_date
                FROM completed_challenges cc
                JOIN challenge_templates ct ON ct.id = cc.challenge_template_id
                LEFT JOIN challenge_flags cf ON cf.id = cc.flag_id
                LEFT JOIN flag_counts fc ON fc.challenge_template_id = cc.challenge_template_id
                LEFT JOIN user_flag_submissions ufs ON ufs.completion_id = cc.id
                WHERE cc.user_id = p_user_id
            )
            SELECT
                'challenge' AS activity_type,
                ca.challenge_template_id AS item_id,
                ca.name AS item_name,
                ca.category AS category,
                COALESCE(ca.points, 0) AS points,
                ca.status = 'solved' AS solved,
                ca.attempt_number,
                ca.started_at AS started_at,
                ca.completed_at AS completed_at,
                ca.status AS status,
                ca.activity_date AS activity_date,
                NULL::TEXT AS icon,
                NULL::badge_color AS color,
                NULL::TEXT AS description,
                'challenge' AS item_type,
                ca.flag_id AS flag_id
            FROM challenge_attempts ca
            WHERE (p_type_filter IS NULL OR ca.status = p_type_filter)
            AND (p_challenge_category IS NULL OR ca.category = p_challenge_category)
        ) UNION ALL (
            SELECT
                'badge' AS activity_type,
                b.id AS item_id,
                b.name AS item_name,
                NULL::challenge_category AS category,
                NULL::BIGINT AS points,
                true AS solved,
                1 AS attempt_number,
                ub.earned_at AS started_at,
                ub.earned_at AS completed_at,
                'badge' AS status,
                ub.earned_at AS activity_date,
                b.icon AS icon,
                b.color AS color,
                b.description AS description,
                'badge' AS item_type,
                NULL::BIGINT AS flag_id
            FROM user_badges ub
            JOIN badges b ON b.id = ub.badge_id
            WHERE ub.user_id = p_user_id
            AND (p_type_filter IS NULL OR p_type_filter = 'badges')
        )
    ) AS co
    WHERE (v_date_start IS NULL OR co.activity_date >= v_date_start)
    ORDER BY co.activity_date DESC, co.item_id
    LIMIT p_limit OFFSET p_offset;
END;
$$;


CREATE FUNCTION get_user_activities_total_count(
    p_user_id BIGINT,
    p_challenge_category challenge_category,
    p_type_filter TEXT,
    p_date_range TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        SELECT COUNT(*) FROM get_user_activities(
            p_user_id,
            p_challenge_category,
            p_type_filter,
            p_date_range,
            NULL,
            NULL
        )
    );
END;
$$;


