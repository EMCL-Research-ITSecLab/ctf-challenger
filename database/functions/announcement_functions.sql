CREATE FUNCTION get_total_announcement_count()
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM announcements)::BIGINT;
END;
$$;


CREATE FUNCTION get_announcements(
    p_limit BIGINT,
    p_offset BIGINT
)
RETURNS TABLE (
    id BIGINT,
    title TEXT,
    content TEXT,
    short_description TEXT,
    importance announcement_importance,
    category announcement_category,
    author TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN QUERY
    SELECT
        a.id::BIGINT,
        a.title::TEXT,
        a.content::TEXT,
        a.short_description::TEXT,
        a.importance::announcement_importance,
        a.category::announcement_category,
        a.author::TEXT,
        a.created_at::TIMESTAMP,
        a.updated_at::TIMESTAMP
    FROM announcements a
    ORDER BY a.created_at DESC
    LIMIT p_limit OFFSET p_offset;
END;
$$;


CREATE FUNCTION create_announcement(
    p_title TEXT,
    p_content TEXT,
    p_short_description TEXT,
    p_importance announcement_importance,
    p_category announcement_category,
    p_author TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
DECLARE
    new_id BIGINT;
BEGIN
    INSERT INTO announcements (
        title,
        content,
        short_description,
        importance,
        category,
        author,
        created_at,
        updated_at
    ) VALUES (
        p_title,
        p_content,
        p_short_description,
        p_importance,
        p_category,
        p_author,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ) RETURNING id INTO new_id;
    RETURN new_id::BIGINT;
END;
$$;


CREATE FUNCTION update_announcement(
    p_id BIGINT,
    p_title TEXT,
    p_content TEXT,
    p_short_description TEXT,
    p_importance announcement_importance,
    p_category announcement_category
)
RETURNS VOID
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    UPDATE announcements
    SET
        title = p_title,
        content = p_content,
        short_description = p_short_description,
        importance = p_importance,
        category = p_category,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_id;
END;
$$;


CREATE FUNCTION announcement_exists(p_id BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM announcements WHERE id = p_id);
END;
$$;


CREATE FUNCTION delete_announcement(p_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    DELETE FROM announcements WHERE id = p_id;
END;
$$;


CREATE FUNCTION get_filtered_announcements(
    p_importance announcement_importance,
    p_date_range TEXT,
    p_limit BIGINT,
    p_offset BIGINT
)
RETURNS TABLE (
    id BIGINT,
    title TEXT,
    content TEXT,
    short_description TEXT,
    importance announcement_importance,
    category announcement_category,
    author TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
DECLARE
    v_start_date TIMESTAMP;
BEGIN
    IF p_date_range = 'today' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 day';
    ELSIF p_date_range = 'week' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 week';
    ELSIF p_date_range = 'month' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 month';
    ELSIF p_date_range = 'year' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 year';
    ELSE
        v_start_date := NULL;
    END IF;

    RETURN QUERY
    SELECT
        a.id::BIGINT,
        a.title::TEXT,
        a.content::TEXT,
        a.short_description::TEXT,
        a.importance::announcement_importance,
        a.category::announcement_category,
        a.author::TEXT,
        a.created_at::TIMESTAMP,
        a.updated_at::TIMESTAMP
    FROM announcements a
    WHERE (p_importance IS NULL OR a.importance = p_importance)
      AND (v_start_date IS NULL OR a.created_at >= v_start_date)
    ORDER BY a.created_at DESC, a.id
    LIMIT p_limit OFFSET p_offset;
END;
$$;


CREATE FUNCTION get_filtered_announcements_count(
    p_importance announcement_importance,
    p_date_range TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        SELECT COUNT(*) FROM get_filtered_announcements(
            p_importance,
            p_date_range,
            NULL,
            NULL
        )
    )::BIGINT;
END;
$$;
