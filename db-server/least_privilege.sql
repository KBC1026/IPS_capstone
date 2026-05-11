CREATE USER IF NOT EXISTS 'webuser'@'192.168.2.100'
  IDENTIFIED BY '<replace-with-strong-password>';

REVOKE ALL PRIVILEGES, GRANT OPTION
  FROM 'webuser'@'192.168.2.100';

GRANT SELECT, INSERT, UPDATE
  ON login_db.users
  TO 'webuser'@'192.168.2.100';

GRANT SELECT, INSERT
  ON login_db.login_logs
  TO 'webuser'@'192.168.2.100';

GRANT INSERT
  ON login_db.attack_logs
  TO 'webuser'@'192.168.2.100';

FLUSH PRIVILEGES;
