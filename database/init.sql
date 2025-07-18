CREATE OR REPLACE FUNCTION assign_lowest_vpn_ip(user_id_param INT)
RETURNS INET AS $$
DECLARE
    selected_ip INET;
BEGIN
    WITH next_ip AS (
        SELECT vpn_static_ip
        FROM vpn_static_ips
        WHERE user_id IS NULL
        ORDER BY vpn_static_ip
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE vpn_static_ips
    SET user_id = user_id_param
    FROM next_ip
    WHERE vpn_static_ips.vpn_static_ip = next_ip.vpn_static_ip
    RETURNING vpn_static_ips.vpn_static_ip INTO selected_ip;

    RETURN selected_ip;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION find_lowest_available_user_id()
    RETURNS INT AS $$
DECLARE
    next_id INT;
BEGIN
    LOCK TABLE users IN EXCLUSIVE MODE;

    SELECT COALESCE(MIN(u1.id + 1), 1) INTO next_id
    FROM users u1
             LEFT JOIN users u2 ON u1.id + 1 = u2.id
    WHERE u2.id IS NULL;

    RETURN next_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION find_lowest_available_machine_template_id()
RETURNS INTEGER AS $$
DECLARE
    next_id INTEGER;
BEGIN
    SELECT COALESCE(MIN(mt1.id + 1), 900000001) INTO next_id
    FROM machine_templates mt1
    LEFT JOIN machine_templates mt2 ON mt1.id + 1 = mt2.id
    WHERE mt1.id BETWEEN 900000000 AND 999999998
      AND mt2.id IS NULL
      AND mt1.id + 1 BETWEEN 900000001 AND 999999999;
    IF EXISTS (
        SELECT 1 FROM machine_templates WHERE id = next_id
    ) THEN
        RAISE EXCEPTION 'No available machine_template ID in range 900000001–999999999';
    END IF;

    RETURN next_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION find_lowest_available_machine_id()
RETURNS INTEGER AS $$
DECLARE
    next_id INTEGER;
BEGIN
    SELECT COALESCE(MIN(mt1.id + 1), 100000001) INTO next_id
    FROM machines mt1
    LEFT JOIN machines mt2 ON mt1.id + 1 = mt2.id
    WHERE mt1.id BETWEEN 100000000 AND 899999998
      AND mt2.id IS NULL
      AND mt1.id + 1 BETWEEN 100000001 AND 899999999;
    IF EXISTS (
        SELECT 1 FROM machines WHERE id = next_id
    ) THEN
        RAISE EXCEPTION 'No available machine_template ID in range 100000001–899999999';
    END IF;

    RETURN next_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION generate_random_default_avatar()
RETURNS VARCHAR AS $$
BEGIN
    RETURN '/assets/avatars/avatar' || (FLOOR(1 + RANDOM() * 3))::INT::TEXT || '.png';
END;
$$ LANGUAGE plpgsql;

CREATE TYPE challenge_category AS ENUM (
    'web',
    'crypto',
    'reverse',
    'forensics',
    'pwn',
    'misc'
);

CREATE TYPE challenge_difficulty AS ENUM (
    'easy',
    'medium',
    'hard'
);

CREATE TYPE announcement_importance AS ENUM (
    'critical',
    'important',
    'normal'
);

CREATE TYPE announcement_category AS ENUM (
    'general',
    'updates',
    'maintenance',
    'events',
    'security'
);

CREATE TABLE vpn_static_ips (
    vpn_static_ip INET PRIMARY KEY,
    user_id INT
);

CREATE TABLE users (
    id INT PRIMARY KEY DEFAULT find_lowest_available_user_id(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(255) DEFAULT generate_random_default_avatar(),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    last_ip VARCHAR(45),
    running_challenge INT,
    is_admin BOOLEAN DEFAULT FALSE,
    vpn_static_ip INET REFERENCES vpn_static_ips(vpn_static_ip)
);


ALTER TABLE vpn_static_ips
ADD CONSTRAINT fk_user_id
FOREIGN KEY (user_id)
REFERENCES users(id);

CREATE TABLE challenge_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category challenge_category NOT NULL,
    difficulty challenge_difficulty NOT NULL,
    image_path VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creator_id INT REFERENCES users(id) ON DELETE SET NULL,
    hint TEXT,
    solution TEXT,
    marked_for_deletion BOOLEAN DEFAULT FALSE
);

CREATE TABLE challenge_subnets
(
    subnet    INET    NOT NULL
        CONSTRAINT challenge_subnet_pkey
            PRIMARY KEY,
    available boolean NOT NULL
);

CREATE TABLE challenges (
    id SERIAL PRIMARY KEY,
    challenge_template_id INT NOT NULL,
    subnet INET REFERENCES challenge_subnets(subnet),
    FOREIGN KEY (challenge_template_id) REFERENCES challenge_templates(id),
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour'),
    used_extensions INT DEFAULT 0
);

ALTER TABLE users
ADD CONSTRAINT fk_running_challenge
FOREIGN KEY (running_challenge)
REFERENCES challenges(id) ON DELETE SET NULL;


CREATE TABLE user_profiles (
    user_id INT PRIMARY KEY,
    full_name VARCHAR(100),
    bio TEXT,
    github_url VARCHAR(255),
    twitter_url VARCHAR(255),
    website_url VARCHAR(255),
    country VARCHAR(50),
    timezone VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE machine_templates (
    id INTEGER PRIMARY KEY DEFAULT find_lowest_available_machine_template_id(),
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    disk_file_path VARCHAR(255) NOT NULL,
    cores INT NOT NULL CHECK (cores > 0),
    ram_gb INT NOT NULL CHECK (ram_gb > 0)
);


CREATE TABLE network_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    accessible BOOLEAN NOT NULL,
    is_dmz BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE domain_templates (
    machine_template_id INT NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (machine_template_id, domain_name)
);


CREATE TABLE network_connection_templates (
    machine_template_id INT NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    network_template_id INT NOT NULL REFERENCES network_templates(id) ON DELETE CASCADE,
    PRIMARY KEY (machine_template_id, network_template_id)
);

CREATE TABLE challenge_flags (
    id SERIAL PRIMARY KEY,
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    flag VARCHAR(255) NOT NULL,
    description TEXT,
    points INT NOT NULL,
    order_index INT DEFAULT 0
);

CREATE TABLE challenge_hints (
    id SERIAL PRIMARY KEY,
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    hint_text TEXT NOT NULL,
    unlock_points INT DEFAULT 0,
    order_index INT DEFAULT 0
);


CREATE TABLE completed_challenges (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    challenge_template_id INT NOT NULL,
    attempts INT NOT NULL DEFAULT 1,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    flag_id INTEGER REFERENCES challenge_flags(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (challenge_template_id) REFERENCES challenge_templates(id)
);

CREATE TABLE badges (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    icon VARCHAR(20),
    color VARCHAR(20),
    rarity VARCHAR(10) DEFAULT 'common' CHECK (rarity IN ('common', 'uncommon', 'rare', 'epic', 'legendary')),
    requirements TEXT NOT NULL
);

CREATE TABLE user_badges (
    user_id INT NOT NULL,
    badge_id INT NOT NULL,
    earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, badge_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (badge_id) REFERENCES badges(id) ON DELETE CASCADE
);

CREATE TABLE announcements (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    short_description VARCHAR(255),
    importance announcement_importance NOT NULL,
    category announcement_category NOT NULL,
    author VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE disk_files (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name VARCHAR(100) NOT NULL,
    proxmox_filename VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, display_name)
);

CREATE TABLE machines
(
    id INTEGER NOT NULL PRIMARY KEY DEFAULT find_lowest_available_machine_id(),
    machine_template_id INTEGER NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE
);

CREATE TABLE networks
(
    id INTEGER NOT NULL PRIMARY KEY,
    network_template_id INTEGER NOT NULL REFERENCES network_templates(id) ON DELETE CASCADE,
    subnet INET NOT NULL,
    host_device VARCHAR NOT NULL
);

CREATE TABLE network_connections
(
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    client_mac MACADDR NOT NULL,
    client_ip  INET    NOT NULL,
    PRIMARY KEY (machine_id, network_id)
);

CREATE TABLE domains
(
    machine_id  INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (machine_id, domain_name)
);

CREATE INDEX idx_machine_templates_challenge ON machine_templates(challenge_template_id);
CREATE INDEX idx_domain_templates_machine ON domain_templates(machine_template_id);
CREATE INDEX idx_network_connection_templates_machine ON network_connection_templates(machine_template_id);
CREATE INDEX idx_network_connection_templates_network ON network_connection_templates(network_template_id);
CREATE INDEX idx_challenge_flags_challenge ON challenge_flags(challenge_template_id);
CREATE INDEX idx_challenge_hints_challenge ON challenge_hints(challenge_template_id);
CREATE INDEX idx_completed_challenges_user_id ON completed_challenges(user_id);
CREATE INDEX idx_challenges_challenge_template_id ON challenges(challenge_template_id);
CREATE INDEX idx_announcements_importance ON announcements(importance);
CREATE INDEX idx_announcements_created_at ON announcements(created_at);
CREATE INDEX idx_disk_files_user_id ON disk_files(user_id);
CREATE INDEX idx_disk_files_upload_date ON disk_files(upload_date);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO badges (name, description, icon, color, rarity, requirements)
VALUES
    ('Web Warrior', 'Solved 5 web challenges', '🕸️', 'gold', 'common', 'Solve 5 web challenges'),
    ('Crypto Expert', 'Solved 5 crypto challenges', '🔐', 'silver', 'common', 'Solve 5 crypto challenges'),
    ('Reverse Engineer', 'Solved 5 reverse challenges', '👁️', 'bronze', 'common', 'Solve 5 reverse challenges'),
    ('Forensic Analyst', 'Solved 5 forensics challenges', '🕵️', 'gold', 'common', 'Solve 5 forensics challenges'),
    ('Binary Buster', 'Solved 5 pwn challenges', '💣', 'silver', 'common', 'Solve 5 pwn challenges'),
    ('Puzzle Master', 'Solved 5 misc challenges', '🧩', 'bronze', 'common', 'Solve 5 misc challenges'),
    ('First Blood', 'First to solve a challenge', '💉', 'red', 'rare', 'Be the first to solve any challenge'),
    ('Speed Runner', 'Solved a challenge in under 5 minutes', '⚡', 'blue', 'uncommon', 'Solve any challenge in under 5 minutes'),
    ('Master Hacker', 'Earn all other badges', '👑', 'rainbow', 'legendary', 'Earn all available badges');
