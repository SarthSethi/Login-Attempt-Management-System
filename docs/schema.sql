-- LAMS version 2 schema, as created by Hibernate (ddl-auto=update) on MySQL 8.0.
-- You do not need to run this file: the application creates and upgrades the tables itself.
-- Upgrading from version 1 adds the five new tables and the new nullable columns; old rows are kept.

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_locks` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `email` varchar(150) NOT NULL,
  `expires_at` datetime(6) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `lifted_at` datetime(6) DEFAULT NULL,
  `lifted_by` varchar(150) DEFAULT NULL,
  `locked_at` datetime(6) NOT NULL,
  `reason` varchar(255) NOT NULL,
  `simulated` bit(1) DEFAULT NULL,
  `lock_type` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_account_locks_email_expires` (`email`,`expires_at`),
  KEY `idx_account_locks_expires` (`expires_at`),
  CONSTRAINT `account_locks_chk_1` CHECK ((`lock_type` in (_utf8mb4'ACCOUNT_IP',_utf8mb4'ACCOUNT')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `admin_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `action` varchar(60) NOT NULL,
  `admin_email` varchar(150) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `detail` varchar(300) DEFAULT NULL,
  `target` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_admin_actions_time` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `blocked_ips` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `blocked_at` datetime(6) NOT NULL,
  `created_by` varchar(150) DEFAULT NULL,
  `expires_at` datetime(6) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `block_level` int DEFAULT NULL,
  `lifted_at` datetime(6) DEFAULT NULL,
  `lifted_by` varchar(150) DEFAULT NULL,
  `reason` varchar(255) NOT NULL,
  `simulated` bit(1) DEFAULT NULL,
  `source` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_blocked_ips_ip_expires` (`ip_address`,`expires_at`),
  KEY `idx_blocked_ips_expires` (`expires_at`),
  CONSTRAINT `blocked_ips_chk_1` CHECK ((`source` in (_utf8mb4'AUTOMATIC',_utf8mb4'MANUAL',_utf8mb4'USER_REPORT')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_allowlist` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `cidr` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `created_by` varchar(150) DEFAULT NULL,
  `note` varchar(150) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_info` (
  `ip_address` varchar(45) NOT NULL,
  `asn` varchar(120) DEFAULT NULL,
  `city` varchar(80) DEFAULT NULL,
  `country` varchar(80) DEFAULT NULL,
  `country_code` varchar(2) DEFAULT NULL,
  `is_hosting` bit(1) DEFAULT NULL,
  `isp` varchar(120) DEFAULT NULL,
  `looked_up_at` datetime(6) NOT NULL,
  `is_mobile` bit(1) DEFAULT NULL,
  `org` varchar(120) DEFAULT NULL,
  `is_proxy` bit(1) DEFAULT NULL,
  `region` varchar(80) DEFAULT NULL,
  `status` varchar(20) NOT NULL,
  PRIMARY KEY (`ip_address`),
  CONSTRAINT `ip_info_chk_1` CHECK ((`status` in (_utf8mb4'OK',_utf8mb4'PRIVATE',_utf8mb4'RESERVED',_utf8mb4'FAILED',_utf8mb4'SIMULATED')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `login_attempts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `attempted_at` datetime(6) NOT NULL,
  `attempted_email` varchar(150) DEFAULT NULL,
  `browser` varchar(60) DEFAULT NULL,
  `device_type` varchar(20) DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `os` varchar(60) DEFAULT NULL,
  `outcome` varchar(20) NOT NULL,
  `reason` varchar(30) DEFAULT NULL,
  `reported` bit(1) DEFAULT NULL,
  `risk_flags` varchar(150) DEFAULT NULL,
  `risk_score` int DEFAULT NULL,
  `simulated` bit(1) DEFAULT NULL,
  `user_agent` varchar(300) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_login_attempts_ip_time` (`ip_address`,`attempted_at`),
  KEY `idx_login_attempts_outcome_time` (`outcome`,`attempted_at`),
  KEY `idx_login_attempts_email_time` (`attempted_email`,`attempted_at`),
  KEY `idx_login_attempts_time` (`attempted_at`),
  CONSTRAINT `login_attempts_chk_1` CHECK ((`outcome` in (_utf8mb4'SUCCESS',_utf8mb4'FAILED',_utf8mb4'BLOCKED'))),
  CONSTRAINT `login_attempts_chk_2` CHECK ((`reason` in (_utf8mb4'WRONG_PASSWORD',_utf8mb4'UNKNOWN_EMAIL',_utf8mb4'ACCOUNT_DISABLED',_utf8mb4'IP_BLOCKED',_utf8mb4'ACCOUNT_IP_LOCKED',_utf8mb4'ACCOUNT_LOCKED')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `security_alerts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `acknowledged` bit(1) NOT NULL,
  `acknowledged_at` datetime(6) DEFAULT NULL,
  `acknowledged_by` varchar(150) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `email` varchar(150) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `message` varchar(500) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `simulated` bit(1) DEFAULT NULL,
  `alert_type` varchar(30) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_security_alerts_time` (`created_at`),
  KEY `idx_security_alerts_ack` (`acknowledged`,`created_at`),
  CONSTRAINT `security_alerts_chk_1` CHECK ((`severity` in (_utf8mb4'LOW',_utf8mb4'MEDIUM',_utf8mb4'HIGH',_utf8mb4'CRITICAL'))),
  CONSTRAINT `security_alerts_chk_2` CHECK ((`alert_type` in (_utf8mb4'BRUTE_FORCE',_utf8mb4'CREDENTIAL_STUFFING',_utf8mb4'HIGH_VOLUME',_utf8mb4'DISTRIBUTED_ATTACK',_utf8mb4'SUSPICIOUS_LOGIN',_utf8mb4'USER_REPORTED')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `email` varchar(150) NOT NULL,
  `enabled` tinyint(1) NOT NULL,
  `name` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_email` (`email`),
  CONSTRAINT `users_chk_1` CHECK ((`role` in (_utf8mb4'USER',_utf8mb4'ADMIN')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
