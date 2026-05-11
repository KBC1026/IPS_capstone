CREATE DATABASE IF NOT EXISTS login_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE login_db;

CREATE TABLE IF NOT EXISTS users (
  id INT NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'user',
  failed_count INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_users_username (username),
  KEY idx_users_locked_until (locked_until)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS login_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  input_id VARCHAR(50) NULL,
  success TINYINT(1) NOT NULL DEFAULT 0,
  client_ip VARCHAR(45) NULL,
  reason VARCHAR(64) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_login_logs_created_at (created_at),
  KEY idx_login_logs_ip_success_created (client_ip, success, created_at),
  KEY idx_login_logs_reason_created (reason, created_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;

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
