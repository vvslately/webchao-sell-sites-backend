-- Add navigation banner columns to config table
ALTER TABLE `config` 
ADD COLUMN `navigation_banner_1` varchar(255) DEFAULT NULL AFTER `banner3_link`,
ADD COLUMN `navigation_link_1` varchar(255) DEFAULT NULL AFTER `navigation_banner_1`,
ADD COLUMN `navigation_banner_2` varchar(255) DEFAULT NULL AFTER `navigation_link_1`,
ADD COLUMN `navigation_link_2` varchar(255) DEFAULT NULL AFTER `navigation_banner_2`,
ADD COLUMN `navigation_banner_3` varchar(255) DEFAULT NULL AFTER `navigation_link_2`,
ADD COLUMN `navigation_link_3` varchar(255) DEFAULT NULL AFTER `navigation_banner_3`,
ADD COLUMN `navigation_banner_4` varchar(255) DEFAULT NULL AFTER `navigation_link_3`,
ADD COLUMN `navigation_link_4` varchar(255) DEFAULT NULL AFTER `navigation_banner_4`;
