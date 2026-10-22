-- Execute este arquivo no MySQL Workbench ou no cliente mysql como administrador.
CREATE DATABASE IF NOT EXISTS vibecheck
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'vibecheck_user'@'localhost' IDENTIFIED BY 'CHANGE_THIS_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER ON vibecheck.* TO 'vibecheck_user'@'localhost';
FLUSH PRIVILEGES;
