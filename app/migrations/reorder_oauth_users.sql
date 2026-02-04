-- Reorder columns in oauth_users table
-- First, create a new table with the correct column order
CREATE TABLE oauth_users_new (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'pacient',
    created_at TIMESTAMPTZ(6) DEFAULT now(),
    updated_at TIMESTAMPTZ(6) DEFAULT now()
);

-- Copy data from old table to new table
INSERT INTO oauth_users_new (id, email, username, password_hash, role, created_at, updated_at)
SELECT id, email, username, password_hash, role, created_at, updated_at
FROM oauth_users;

-- Drop the old table
DROP TABLE oauth_users;

-- Rename the new table to the original name
ALTER TABLE oauth_users_new RENAME TO oauth_users;
