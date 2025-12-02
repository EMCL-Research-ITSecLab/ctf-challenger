CREATE FUNCTION get_user_badges_data(
    p_user_id BIGINT
)
RETURNS TABLE (
    id BIGINT,
    name TEXT,
    description TEXT,
    icon TEXT,
    rarity badge_rarity,
    requirements TEXT,
    earned_at TIMESTAMP,
    earned BOOLEAN
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN QUERY
    SELECT
        b.id::BIGINT,
        b.name::TEXT,
        b.description::TEXT,
        b.icon::TEXT,
        b.rarity::badge_rarity,
        b.requirements::TEXT,
        ub.earned_at::TIMESTAMP,
        CASE WHEN ub.user_id IS NULL THEN false::BOOLEAN ELSE true::BOOLEAN END as earned
    FROM badges b
    LEFT JOIN user_badges ub ON ub.badge_id = b.id AND ub.user_id = p_user_id
    ORDER BY b.rarity DESC, b.name, b.id;
END;
$$;


CREATE FUNCTION get_user_solved_challenge_count(
    p_user_id BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        WITH user_completed_flags AS (
            SELECT
                user_id,
                challenge_template_id,
                flag_id
            FROM completed_challenges
            WHERE user_id = p_user_id
        ),
         challenge_total_flags AS (
             SELECT
                 challenge_template_id,
                 COUNT(*) as total_flags
             FROM challenge_flags
             GROUP BY challenge_template_id
         ),
         user_solved_challenges AS (
             SELECT
                 ucf.user_id,
                 ucf.challenge_template_id
             FROM user_completed_flags ucf
                      JOIN challenge_total_flags ctf ON ucf.challenge_template_id = ctf.challenge_template_id
             GROUP BY ucf.user_id, ucf.challenge_template_id
             HAVING COUNT(DISTINCT ucf.flag_id) = MAX(ctf.total_flags)
         )
        SELECT COUNT(*)
        FROM user_solved_challenges
        WHERE user_id = p_user_id
    )::BIGINT;
END;
$$;


CREATE FUNCTION get_user_solved_challenge_count_in_category(
    p_user_id BIGINT,
    p_category challenge_category
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        WITH user_completed_flags AS (
            SELECT
                cc.user_id,
                cc.challenge_template_id,
                cc.flag_id
            FROM completed_challenges cc
            WHERE cc.user_id = p_user_id
        ),
        challenge_total_flags AS (
            SELECT
                cf.challenge_template_id,
                COUNT(*) as total_flags
            FROM challenge_flags cf
            JOIN challenge_templates ct ON ct.id = cf.challenge_template_id
            WHERE ct.category = p_category
            GROUP BY cf.challenge_template_id
        ),
        user_solved_challenges AS (
            SELECT
                ucf.user_id,
                ucf.challenge_template_id
            FROM user_completed_flags ucf
            JOIN challenge_total_flags ctf ON ucf.challenge_template_id = ctf.challenge_template_id
            GROUP BY ucf.user_id, ucf.challenge_template_id
            HAVING COUNT(DISTINCT ucf.flag_id) = MAX(ctf.total_flags)
        )
        SELECT COUNT(*)
        FROM user_solved_challenges
        WHERE user_id = p_user_id
    )::BIGINT;
END;
$$;


CREATE FUNCTION get_user_total_points(
    p_user_id BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        SELECT COALESCE(SUM(cf.points), 0)
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cf.id = cc.flag_id
        WHERE cc.user_id = p_user_id
    )::BIGINT;
END;
$$;


CREATE FUNCTION get_user_earned_badges_count_exclude_one(
    p_user_id BIGINT,
    p_exclude_badge_id BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        SELECT COUNT(*)
        FROM user_badges ub
        JOIN badges b ON b.id = ub.badge_id
        WHERE ub.user_id = p_user_id
        AND b.id != p_exclude_badge_id
    )::BIGINT;
END;
$$;


CREATE FUNCTION get_total_badge_count_exclude_one(
    p_exclude_badge_id BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM badges WHERE id != p_exclude_badge_id)::BIGINT;
END;
$$;


CREATE FUNCTION get_total_badge_count_and_user_earned_count(
    p_user_id BIGINT
)
RETURNS TABLE (
    total_badges BIGINT,
    earned_badges BIGINT
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM badges)::BIGINT AS total_badges,
        (SELECT COUNT(*) FROM user_badges WHERE user_id = p_user_id)::BIGINT AS earned_badges;
END;
$$;





