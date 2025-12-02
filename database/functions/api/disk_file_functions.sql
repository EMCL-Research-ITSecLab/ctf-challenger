CREATE FUNCTION get_user_disk_files(
    p_user_id BIGINT
)
RETURNS TABLE (
    id BIGINT,
    display_name TEXT,
    upload_date TIMESTAMP
)
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN QUERY
    SELECT
        d.id::BIGINT,
        d.display_name::TEXT,
        d.upload_date::TIMESTAMP
    FROM disk_files d
    WHERE d.user_id = p_user_id
    ORDER BY d.upload_date DESC, d.id;
END;
$$;


CREATE FUNCTION is_duplicate_file_name(
    p_user_id BIGINT,
    p_display_name TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM disk_files
        WHERE user_id = p_user_id
        AND display_name = p_display_name
    )::BOOLEAN;
END;
$$;


CREATE FUNCTION add_user_disk_file(
    p_user_id BIGINT,
    p_display_name TEXT,
    p_proxmox_filename TEXT
) RETURNS VOID
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    INSERT INTO disk_files (user_id, display_name, proxmox_filename)
    VALUES (p_user_id, p_display_name, p_proxmox_filename);
END;
$$;


CREATE FUNCTION get_filename_by_id(
    p_ova_id BIGINT,
    p_user_id BIGINT
) RETURNS TEXT
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    RETURN (
        SELECT proxmox_filename FROM disk_files
        WHERE id = p_ova_id AND user_id = p_user_id
    )::TEXT;
END;
$$;


CREATE FUNCTION delete_user_disk_file(
    p_ova_id BIGINT,
    p_user_id BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SET plpgsql.variable_conflict = 'use_column'
AS $$
BEGIN
    DELETE FROM disk_files
    WHERE id = p_ova_id AND user_id = p_user_id;
END;
$$;