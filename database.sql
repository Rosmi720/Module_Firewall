CREATE TABLE IF NOT EXISTS `module_firewall_settings` (
    `key` VARCHAR(64) NOT NULL PRIMARY KEY,
    `value` TEXT NOT NULL,
    `updated_at` INT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `module_firewall_history` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `ip` VARCHAR(45) NOT NULL,
    `jail` VARCHAR(32) NOT NULL,
    `action` ENUM('BAN', 'UNBAN') NOT NULL,
    `reason` VARCHAR(255) NULL,
    `date` INT UNSIGNED NOT NULL,
    INDEX `idx_ip` (`ip`),
    INDEX `idx_date` (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `module_firewall_rules` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `rule_key` VARCHAR(64) NOT NULL UNIQUE,
    `name` VARCHAR(128) NOT NULL,
    `category` ENUM('default', 'custom') NOT NULL DEFAULT 'custom',
    `enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `port` VARCHAR(128) NOT NULL DEFAULT 'all',
    `protocol` VARCHAR(16) NOT NULL DEFAULT 'tcp',
    `filter_regex` TEXT NULL,
    `log_path` VARCHAR(255) NULL,
    `maxretry` INT UNSIGNED NOT NULL DEFAULT 5,
    `findtime` INT UNSIGNED NOT NULL DEFAULT 600,
    `bantime` INT UNSIGNED NOT NULL DEFAULT 3600,
    `action_type` VARCHAR(64) NOT NULL DEFAULT 'iptables-multiport',
    `description` TEXT NULL,
    `created_at` INT UNSIGNED NOT NULL,
    `updated_at` INT UNSIGNED NOT NULL,
    INDEX `idx_category` (`category`),
    INDEX `idx_enabled` (`enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

