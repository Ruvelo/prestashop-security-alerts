CREATE TABLE IF NOT EXISTS `PREFIX_ruvelo_securityalerts_finding` (
  `id_finding` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `finding_key` VARCHAR(191) NOT NULL,
  `data` MEDIUMTEXT NOT NULL,
  `exploited` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  `notified` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  `date_add` DATETIME NOT NULL,
  PRIMARY KEY (`id_finding`),
  UNIQUE KEY `finding_key` (`finding_key`),
  KEY `notified` (`notified`)
) ENGINE=ENGINE_TYPE DEFAULT CHARSET=utf8mb4;
