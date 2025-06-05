-- Add is_google_account column to users table
ALTER TABLE users ADD COLUMN is_google_account TINYINT(1) DEFAULT 0;

-- Update existing users to be non-Google accounts
UPDATE users SET is_google_account = 0 WHERE is_google_account IS NULL;