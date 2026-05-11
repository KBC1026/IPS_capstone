USE login_db;

-- Step 1. This must return zero rows before applying the username UNIQUE key.
SELECT username, COUNT(*) AS duplicate_count
FROM users
GROUP BY username
HAVING COUNT(*) > 1;

-- Step 2. Check existing indexes. Skip an ADD KEY line below if the index already exists.
SELECT table_name, index_name
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name IN ('users', 'login_logs')
  AND index_name IN (
    'uk_users_username',
    'idx_users_locked_until',
    'idx_login_logs_created_at',
    'idx_login_logs_ip_success_created',
    'idx_login_logs_reason_created'
  )
ORDER BY table_name, index_name;

-- Step 3. Apply after Step 1 and Step 2 are checked.
ALTER TABLE users
  MODIFY username VARCHAR(50) NOT NULL,
  MODIFY password_hash VARCHAR(255) NOT NULL,
  MODIFY role VARCHAR(20) NOT NULL DEFAULT 'user',
  MODIFY failed_count INT NOT NULL DEFAULT 0,
  ADD UNIQUE KEY uk_users_username (username),
  ADD KEY idx_users_locked_until (locked_until);

ALTER TABLE login_logs
  MODIFY id BIGINT NOT NULL AUTO_INCREMENT,
  MODIFY success TINYINT(1) NOT NULL DEFAULT 0,
  MODIFY client_ip VARCHAR(45) NULL,
  MODIFY reason VARCHAR(64) NULL,
  MODIFY created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD KEY idx_login_logs_created_at (created_at),
  ADD KEY idx_login_logs_ip_success_created (client_ip, success, created_at),
  ADD KEY idx_login_logs_reason_created (reason, created_at);

CREATE TABLE IF NOT EXISTS attack_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  attack_type VARCHAR(64) NOT NULL,
  attacker_ip VARCHAR(45) NULL,
  payload TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_attack_logs_created_at (created_at),
  KEY idx_attack_logs_attacker_created (attacker_ip, created_at),
  KEY idx_attack_logs_type_created (attack_type, created_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;
