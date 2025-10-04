/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

DROP TABLE IF EXISTS `auth_sites`;
CREATE TABLE `auth_sites` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `website_name` varchar(150) NOT NULL,
  `admin_user` varchar(100) NOT NULL,
  `admin_password` varchar(255) NOT NULL,
  `expiredDay` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_customer` (`customer_id`)
) ENGINE=InnoDB AUTO_INCREMENT=43 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `categories`;
CREATE TABLE `categories` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `parent_id` int DEFAULT NULL,
  `title` varchar(150) NOT NULL,
  `subtitle` varchar(255) DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `featured` tinyint(1) DEFAULT '0',
  `isActive` tinyint(1) DEFAULT '1',
  `priority` int NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `category` (`category`),
  KEY `idx_parent_id` (`parent_id`),
  CONSTRAINT `categories_ibfk_1` FOREIGN KEY (`parent_id`) REFERENCES `categories` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=53 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `config`;
CREATE TABLE `config` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `owner_phone` varchar(20) NOT NULL,
  `site_name` varchar(100) DEFAULT NULL,
  `site_logo` varchar(255) DEFAULT NULL,
  `meta_title` varchar(255) DEFAULT NULL,
  `meta_description` varchar(500) DEFAULT NULL,
  `meta_keywords` varchar(500) DEFAULT NULL,
  `meta_author` varchar(100) DEFAULT NULL,
  `discord_link` varchar(255) DEFAULT NULL,
  `discord_webhook` varchar(255) DEFAULT NULL,
  `banner_link` varchar(255) DEFAULT NULL,
  `banner2_link` varchar(255) DEFAULT NULL,
  `banner3_link` varchar(255) DEFAULT NULL,
  `background_image` varchar(255) DEFAULT NULL,
  `footer_image` varchar(255) DEFAULT NULL,
  `load_logo` varchar(255) DEFAULT NULL,
  `footer_logo` varchar(255) DEFAULT NULL,
  `theme` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ad_banner` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `product_stock`;
CREATE TABLE `product_stock` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `product_id` int NOT NULL,
  `license_key` varchar(255) NOT NULL,
  `sold` tinyint(1) DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `product_id` (`product_id`),
  CONSTRAINT `product_stock_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1023 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `products`;
CREATE TABLE `products` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `category_id` int NOT NULL,
  `title` varchar(150) NOT NULL,
  `subtitle` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `reseller_price` decimal(10,2) DEFAULT NULL,
  `stock` int DEFAULT '0',
  `duration` varchar(50) DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `download_link` varchar(1000) DEFAULT NULL,
  `isSpecial` tinyint(1) DEFAULT '0',
  `featured` tinyint(1) DEFAULT '0',
  `isActive` tinyint(1) DEFAULT '1',
  `isWarrenty` tinyint(1) DEFAULT '0',
  `warrenty_text` varchar(1000) DEFAULT NULL,
  `primary_color` char(7) DEFAULT NULL,
  `secondary_color` char(7) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `priority` int NOT NULL DEFAULT '0',
  `discount_percent` tinyint unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `category_id` (`category_id`),
  CONSTRAINT `products_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`),
  CONSTRAINT `products_chk_1` CHECK ((`discount_percent` between 0 and 100))
) ENGINE=InnoDB AUTO_INCREMENT=65 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `resell_topup_history`;
CREATE TABLE `resell_topup_history` (
  `topup_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `method` enum('bank','wallet','card') NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `slip_url` varchar(255) DEFAULT NULL,
  `status` enum('pending','success','failed') DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`topup_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `resell_topup_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `resell_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `resell_transactions`;
CREATE TABLE `resell_transactions` (
  `transac_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `type` enum('purchase','withdraw','transfer') NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `description` text,
  `status` enum('pending','success','failed') DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`transac_id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `resell_transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `resell_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `resell_users`;
CREATE TABLE `resell_users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(150) DEFAULT NULL,
  `role` enum('admin','user','moderator') DEFAULT 'user',
  `balance` decimal(10,2) DEFAULT '0.00',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `roles`;
CREATE TABLE `roles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `rank_name` varchar(100) NOT NULL,
  `can_edit_categories` tinyint(1) DEFAULT '0',
  `can_edit_products` tinyint(1) DEFAULT '0',
  `can_edit_users` tinyint(1) DEFAULT '0',
  `can_edit_orders` tinyint(1) DEFAULT '0',
  `can_manage_keys` tinyint(1) DEFAULT '0',
  `can_view_reports` tinyint(1) DEFAULT '0',
  `can_manage_promotions` tinyint(1) DEFAULT '0',
  `can_manage_settings` tinyint(1) DEFAULT '0',
  `can_access_reseller_price` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `theme_settings`;
CREATE TABLE `theme_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `primary_color` varchar(7) NOT NULL,
  `secondary_color` varchar(7) NOT NULL,
  `background_color` varchar(7) NOT NULL,
  `text_color` varchar(7) NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `theme_mode` varchar(10) DEFAULT 'light',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `topups`;
CREATE TABLE `topups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `user_id` int NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `method` varchar(50) NOT NULL,
  `transaction_ref` varchar(100) DEFAULT NULL,
  `status` enum('pending','success','failed') DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_topups_user_id` (`user_id`),
  CONSTRAINT `topups_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `transaction_items`;
CREATE TABLE `transaction_items` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `bill_number` varchar(50) NOT NULL,
  `transaction_id` int NOT NULL,
  `product_id` int NOT NULL,
  `quantity` int NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `license_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_transaction_items_transaction_id` (`transaction_id`),
  KEY `idx_transaction_items_product_id` (`product_id`),
  KEY `transaction_items_ibfk_3` (`license_id`),
  CONSTRAINT `transaction_items_ibfk_1` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`id`) ON DELETE CASCADE,
  CONSTRAINT `transaction_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE,
  CONSTRAINT `transaction_items_ibfk_3` FOREIGN KEY (`license_id`) REFERENCES `product_stock` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `transactions`;
CREATE TABLE `transactions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `bill_number` varchar(50) NOT NULL,
  `user_id` int NOT NULL,
  `total_price` decimal(10,2) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_transactions_user_id` (`user_id`),
  KEY `idx_transactions_created_at` (`created_at`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` varchar(100) NOT NULL,
  `discord_id` varchar(50) DEFAULT NULL,
  `fullname` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `money` decimal(10,2) DEFAULT '0.00',
  `points` int DEFAULT '0',
  `role` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT 'member',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `auth_sites` (`id`, `customer_id`, `website_name`, `admin_user`, `admin_password`, `expiredDay`, `created_at`) VALUES
(1, '1', 'modelv', 'admin', 'admin', '2025-10-22', '2024-10-01 11:08:56'),
(2, '2', 'expire', 'admin', 'admin', '2020-10-22', '2024-10-01 11:08:56'),
(39, '3', 'realmasa', 'realmasa918682', 'c69591e36d34a857e9d8a6dec8d29f7b:1e45764eff636fd28256f8edad85b1d8', '2025-11-03', '2025-10-04 14:07:33'),
(40, '4', 'cartier', 'cartier141529', '4a02c36987ddabc1ff2f0374be4dc4ef:cc21661212cf0a56b158bdce6727365e', '2025-12-03', '2025-10-04 14:11:08'),
(41, '5', 'kiddyxstore', 'kiddyxstore821203', 'add96f523b335488ac762ec818ae4539:87a7d09da8ff87512125d0818d5316c3', '2025-11-03', '2025-10-04 14:19:41'),
(42, '6', 'death', 'aekwannoy323599', '3d74580c027548ccad26efb14d3ea028:add91181f6dc0695e64c86974f486617', '2025-11-03', '2025-10-04 14:25:36');
INSERT INTO `categories` (`id`, `customer_id`, `parent_id`, `title`, `subtitle`, `image`, `category`, `featured`, `isActive`, `priority`, `created_at`) VALUES
(2, '1', NULL, 'Rov Hub', '', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'RovHub', 0, 1, 0, '2025-09-29 15:26:03'),
(3, '1', NULL, 'Valorant Hub', '', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'ValorantHub', 0, 0, 0, '2025-09-29 15:26:03'),
(47, '3', NULL, 'androssy Category', 'Category for androssy', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'androssy_category', 0, 1, 0, '2025-10-04 13:29:07'),
(48, '3', NULL, 'realmasa Category', 'Category for realmasa', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'realmasa_category', 0, 1, 0, '2025-10-04 14:07:38'),
(49, '4', NULL, 'cartier Category', 'Category for cartier', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'cartier_category', 0, 1, 0, '2025-10-04 14:11:09'),
(50, '4', NULL, 'adsd', NULL, 'https://cartier.vhouse.online/', NULL, 0, 1, 0, '2025-10-04 14:13:28'),
(51, '5', NULL, 'kiddyxstore Category', 'Category for kiddyxstore', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'kiddyxstore_category', 0, 1, 0, '2025-10-04 14:19:43'),
(52, '6', NULL, 'aekwannoy Category', 'Category for aekwannoy', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', 'aekwannoy_category', 0, 1, 0, '2025-10-04 14:25:38');
INSERT INTO `config` (`id`, `customer_id`, `owner_phone`, `site_name`, `site_logo`, `meta_title`, `meta_description`, `meta_keywords`, `meta_author`, `discord_link`, `discord_webhook`, `banner_link`, `banner2_link`, `banner3_link`, `background_image`, `footer_image`, `load_logo`, `footer_logo`, `theme`, `created_at`, `updated_at`, `ad_banner`) VALUES
(1, '1', '0843460416', 'XXXX', 'https://www.getampx.com/images/logo/amparexlogowithname.png', 'XXX - Template', 'ร้านขายโค้ด เกม และสินค้า Digital แท้ ปลอดภัย 100%', 'เกม, โค้ดแท้, steam, ps5, xbox, digital store', 'XXX - ประกาศ', 'https://discord.gg/abcd1234', 'https://discord.com/api/webhooks/1421119563067822204/qR5GXn9EtK_o-HLyWa5utKzl8dIoQsOlUd88IEOquRjAApdUj7M5Q7Xi21rRBTpxZqWh', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://cdn.shopify.com/s/files/1/0515/2702/4839/files/COUGH_SYRUP_BANNER.jpg?v=1729558083https://cdn.shopify.com/s/files/1/0515/2702/4839/files/COUGH_SYRUP_BANNER.jpg?v=1729558083', 'https://cdn.shopify.com/s/files/1/0515/2702/4839/files/COUGH_SYRUP_BANNER.jpg?v=1729558083', 'https://xenonhub.pro/logos/xenonhub.png', 'https://xenonhub.pro/logos/xenonhub.png', 'Dark mode', '2025-09-29 13:28:13', '2025-10-04 11:44:15', NULL),
(22, '3', '0000000000', 'realmasa', 'https://xenonhub.pro/logos/xenonhub.png', '(⭐) realmasa - Digital Store', 'Welcome to realmasa - Your trusted digital products store', 'digital, products, store, gaming', 'realmasa Admin', NULL, NULL, 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', NULL, NULL, NULL, NULL, 'Dark mode', '2025-10-04 14:07:45', '2025-10-04 14:07:45', NULL),
(23, '4', '0000002323', 'cartier', 'https://xenonhub.pro/logos/xenonhub.png', '(⭐) cartier - Digital Store', 'Welcome to cartier - Your trusted digital products store', 'digital, products, store, gaming', 'cartier Admin', NULL, NULL, 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', NULL, NULL, NULL, NULL, 'Dark mode', '2025-10-04 14:11:13', '2025-10-04 14:13:56', NULL),
(24, '5', '0000000000', 'kiddyxstore', 'https://xenonhub.pro/logos/xenonhub.png', '(⭐) kiddyxstore - Digital Store', 'Welcome to kiddyxstore - Your trusted digital products store', 'digital, products, store, gaming', 'kiddyxstore Admin', NULL, NULL, 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', NULL, NULL, NULL, NULL, 'Dark mode', '2025-10-04 14:19:46', '2025-10-04 14:19:46', NULL),
(25, '6', '0000000000', 'aekwannoy', 'https://xenonhub.pro/logos/xenonhub.png', '(⭐) aekwannoy - Digital Store', 'Welcome to aekwannoy - Your trusted digital products store', 'digital, products, store, gaming', 'aekwannoy Admin', NULL, NULL, 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', 'https://img2.pic.in.th/pic/2000x5009e8abd4c1b6fc6df.jpg', NULL, NULL, NULL, NULL, 'Dark mode', '2025-10-04 14:25:42', '2025-10-04 14:25:42', NULL);
INSERT INTO `product_stock` (`id`, `customer_id`, `product_id`, `license_key`, `sold`, `created_at`) VALUES
(1019, '4', 60, 'xxx', 0, '2025-10-04 14:12:43'),
(1020, '5', 64, 'dsadsa', 1, '2025-10-04 14:42:08'),
(1021, '5', 64, 'dasdsa', 0, '2025-10-04 14:42:08'),
(1022, '5', 64, 'dasdsadas', 0, '2025-10-04 14:42:08');
INSERT INTO `products` (`id`, `customer_id`, `category_id`, `title`, `subtitle`, `price`, `reseller_price`, `stock`, `duration`, `image`, `download_link`, `isSpecial`, `featured`, `isActive`, `isWarrenty`, `warrenty_text`, `primary_color`, `secondary_color`, `created_at`, `priority`, `discount_percent`) VALUES
(33, '1', 2, 'ad', 'ad', '12.00', NULL, 0, NULL, 'http://localhost:5173/', NULL, 0, 0, 1, 0, NULL, NULL, NULL, '2025-10-02 17:46:21', 0, 0),
(59, '3', 48, 'Sample Product', 'This is a sample product for your new site', '10.00', '8.00', 100, '30 days', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', NULL, 0, 1, 1, 0, NULL, '#ff0000', '#b3ffc7', '2025-10-04 14:07:43', 0, 0),
(60, '4', 49, 'Sample Product', 'This is a sample product for your new site', '10.00', '8.00', 101, '30 days', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', NULL, 0, 1, 1, 0, NULL, '#ff0000', '#b3ffc7', '2025-10-04 14:11:12', 0, 0),
(61, '4', 49, 'asdadasd', 'adadsa', '10.00', NULL, 0, NULL, 'https://cartier.vhouse.online/', NULL, 0, 0, 1, 0, NULL, NULL, NULL, '2025-10-04 14:13:12', 0, 0),
(62, '5', 51, 'Sample Product', 'This is a sample product for your new site', '10.00', '8.00', 100, '30 days', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', NULL, 0, 1, 1, 0, NULL, '#ff0000', '#b3ffc7', '2025-10-04 14:19:45', 0, 0),
(63, '6', 52, 'Sample Product', 'This is a sample product for your new site', '10.00', '8.00', 100, '30 days', 'https://img5.pic.in.th/file/secure-sv1/1640x500.jpg', NULL, 0, 1, 1, 0, NULL, '#ff0000', '#b3ffc7', '2025-10-04 14:25:41', 0, 10),
(64, '5', 51, 'ทดสอบ ถาวร', 'ทดสอบ', '100.00', NULL, 2, NULL, 'https://img2.pic.in.th/pic/Kiddyxstore-Poster-02-1.webp', NULL, 0, 0, 1, 1, 'รับประกันถาวร', '#00ff1e', NULL, '2025-10-04 14:41:06', 0, 0);

INSERT INTO `resell_transactions` (`transac_id`, `user_id`, `type`, `amount`, `description`, `status`, `created_at`) VALUES
(42, 15, 'purchase', '200.00', 'androssy;Username: androssy954165@gmail.com;Password: REALMASA;ต่ออายุ', 'success', '2025-10-04 13:27:12'),
(43, 15, 'purchase', '200.00', 'androssy;ต่ออายุ', 'success', '2025-10-04 13:29:07'),
(44, 16, 'purchase', '200.00', 'realmasa;Username: realmasa918682@gmail.com;Password: dion;ต่ออายุ', 'success', '2025-10-04 14:07:36'),
(45, 16, 'purchase', '200.00', 'cartier;Username: cartier474135@gmail.com;Password: aaa;ต่ออายุ', 'success', '2025-10-04 14:11:09'),
(46, 16, 'purchase', '200.00', 'cartier;Username: cartier141529@gmail.com;Password: adsasdadasd;ต่ออายุ', 'success', '2025-10-04 14:15:14'),
(47, 16, 'purchase', '200.00', 'kiddyxstore;Username: kiddyxstore821203@gmail.com;Password: 0927014505za;ต่ออายุ', 'success', '2025-10-04 14:19:42'),
(48, 16, 'purchase', '200.00', 'aekwannoy;Username: aekwannoy323599@gmail.com;Password: admin;ต่ออายุ', 'success', '2025-10-04 14:25:37');
INSERT INTO `resell_users` (`user_id`, `username`, `password`, `email`, `role`, `balance`, `created_at`) VALUES
(1, 'Teerachat20005', '$2b$10$MGAH6Gklr/1qNsOA3MPLRuAOYdXXuKWNDe5yiwjbBpXkNGVtuJnWy', 'Teerachat20005@gmail.com', 'user', '3600.00', '2025-10-03 15:56:32'),
(15, 'REALMASA', '$2b$10$NS5tzADQ9UpwZbGmMG/5g.MWOKt.WtH7HZj/9zQllKMnQGIyMNE2O', 'Teerachat200xx05@gmail.com', 'user', '100.00', '2025-10-04 13:23:25'),
(16, 'test_user_for_dev', '$2a$10$KVVdMB8L0uPw5wdeir8QqO3UHhE0mpnunaegsBoX2K8cZOR/RO.AO', 'test@gmail.com', 'user', '49000.00', '2025-10-04 14:05:25'),
(17, 'beam123', '$2a$10$.ImxH.GwFaBNeVBv8NgQQ.clteDQzm24NwFRdEfAoDBmg9OR9ogcS', NULL, 'user', '0.00', '2025-10-04 14:16:38');
INSERT INTO `roles` (`id`, `customer_id`, `rank_name`, `can_edit_categories`, `can_edit_products`, `can_edit_users`, `can_edit_orders`, `can_manage_keys`, `can_view_reports`, `can_manage_promotions`, `can_manage_settings`, `can_access_reseller_price`, `created_at`) VALUES
(1, '1', 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0, '2025-09-14 10:43:57'),
(31, '3', 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0, '2025-10-04 14:07:39'),
(32, '4', 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0, '2025-10-04 14:11:10'),
(33, '5', 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0, '2025-10-04 14:19:43'),
(34, '6', 'admin', 1, 1, 1, 1, 1, 1, 1, 1, 0, '2025-10-04 14:25:39');
INSERT INTO `theme_settings` (`id`, `customer_id`, `primary_color`, `secondary_color`, `background_color`, `text_color`, `updated_at`, `theme_mode`) VALUES
(1, '1', '#00ff04', '#b3ffc7', '#000000', '#FFFFFF', '2025-10-04 12:11:28', 'dark'),
(29, '3', '#2994ff', '#29f8ff', '#FFFFFF', '#000000', '2025-10-04 14:07:40', 'dark'),
(30, '4', '#2994ff', '#29f8ff', '#FFFFFF', '#000000', '2025-10-04 14:11:10', 'dark'),
(31, '5', '#2994ff', '#29f8ff', '#FFFFFF', '#000000', '2025-10-04 14:19:44', 'dark'),
(32, '6', '#2994ff', '#29f8ff', '#FFFFFF', '#000000', '2025-10-04 14:25:39', 'dark');

INSERT INTO `transaction_items` (`id`, `customer_id`, `bill_number`, `transaction_id`, `product_id`, `quantity`, `price`, `created_at`, `license_id`) VALUES
(13, '5', 'BILL-1759589298979-0UXSA62GK', 13, 64, 1, '100.00', '2025-10-04 14:48:19', 1020);
INSERT INTO `transactions` (`id`, `customer_id`, `bill_number`, `user_id`, `total_price`, `created_at`, `updated_at`) VALUES
(13, '5', 'BILL-1759589298979-0UXSA62GK', 33, '100.00', '2025-10-04 14:48:19', '2025-10-04 14:48:19');
INSERT INTO `users` (`id`, `customer_id`, `discord_id`, `fullname`, `email`, `password`, `money`, `points`, `role`, `created_at`) VALUES
(2, '1', NULL, 'admin', 'admin@gmail.com', '$2b$10$J5oZxnoedJr9PWfgAgGCBuxB20QjAGD2wbx63de14HW/4oifUAfPK', '986.00', 0, 'admin', '2025-10-02 21:41:21'),
(31, '3', NULL, 'realmasa Admin', 'realmasa918682@gmail.com', '$2a$10$FJLMVqynN/9AVPlhK2OmeOKsNiNMDXhN7W48uJyP2t6m3aqkoUgZy', '0.00', 0, 'admin', '2025-10-04 14:07:42'),
(32, '4', NULL, 'cartier Admin', 'cartier474135@gmail.com', '$2a$10$mfNbsNPMCIdYEwe45qLCP.TU/5Q67Yx3wFswqACSw54/loaW/ebA6', '0.00', 0, 'admin', '2025-10-04 14:11:11'),
(33, '5', NULL, 'kiddyxstore Admin', 'kiddyxstore821203@gmail.com', '$2a$10$Sq1pCDXBLA7gEZ52BZKHLuSQtNMGkyBSpHnNDsPJ.sD5ZlFUOvMzS', '999900.00', 0, 'admin', '2025-10-04 14:19:45'),
(34, '6', NULL, 'aekwannoy Admin', 'aekwannoy323599@gmail.com', '$2a$10$f5RrPDuNZkB7lAPF1Xi7xe8iloJ.OgK.ysdEasTm7OJF./nZ/Fe1i', '0.00', 0, 'admin', '2025-10-04 14:25:41');


/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;