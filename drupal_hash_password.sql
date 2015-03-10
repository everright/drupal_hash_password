/**
 * Ported the function user_hash_password of Drupal to MySQL.
 *
 * Author: Everright Chen
 * Email : everright.chen@gmail.com
 * Web   : http://www.everright.cn
 */

DELIMITER $$

/**
 * Returns a string for mapping an int to the corresponding base 64 character.
 */
DROP FUNCTION IF EXISTS _password_itoa64;
CREATE FUNCTION _password_itoa64()

RETURNS VARCHAR(64) CHARACTER SET utf8

BEGIN
  RETURN './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

END; $$

/**
 * Generates a random base 64-encoded salt prefixed with settings for the hash.
 *
 * Proper use of salts may defeat a number of attacks, including:
 *  - The ability to try candidate passwords against multiple hashes at once.
 *  - The ability to use pre-hashed lists of candidate passwords.
 *  - The ability to determine whether two users have the same (or different)
 *    password without actually having to guess one of the passwords.
 *
 * @param $count_log2
 *   Integer that determines the number of iterations used in the hashing
 *   process. A larger value is more secure, but takes more time to complete.
 *
 * @return
 *   A 12 character string containing the iteration count and a random salt.
 */
DROP FUNCTION IF EXISTS _password_generate_salt;
CREATE FUNCTION _password_generate_salt(
  count_log2 INT
)

RETURNS VARCHAR(12) CHARACTER SET utf8

BEGIN
  DECLARE output VARCHAR(255) CHARACTER SET utf8 DEFAULT '$S$';

  IF (count_log2 < 7) THEN
    SET count_log2 = 7;
  ELSEIF (count_log2 > 30) THEN
    SET count_log2 = 30;
  END IF;

  SET output = CONCAT(output, SUBSTRING(_password_itoa64(), count_log2 + 1, 1), _password_base64_encode(CONV(FLOOR(RAND() * 0x1000000), 10, 16), 6));

  RETURN output;

END; $$

/**
 * Encodes bytes into printable base 64 using the *nix standard from crypt().
 *
 * @param $input
 *   The string containing bytes to encode.
 * @param $count
 *   The number of characters (bytes) to encode.
 *
 * @return
 *   Encoded string
 */
DROP FUNCTION IF EXISTS _password_base64_encode;
CREATE FUNCTION _password_base64_encode(
  input BLOB,
  count INT
)

RETURNS VARCHAR(255) CHARACTER SET utf8

BEGIN
  DECLARE output, itoa64 VARCHAR(255) CHARACTER SET utf8 DEFAULT '';
  DECLARE value CHAR(10) CHARACTER SET utf8;
  DECLARE i INT DEFAULT 0;

  IF (count < 1) THEN
    SET count = 1;
  END IF;

  SET itoa64 = _password_itoa64();

  myloop: WHILE i < count DO

    SET i = i + 1;
    SET value = ORD(SUBSTRING(input, i, 1));
    SET output = CONCAT(output, SUBSTRING(itoa64, (value & 0x3f) + 1, 1));

    IF (i < count) THEN
      SET value = value | (ORD(SUBSTRING(input, i + 1, 1)) << 8);
    END IF;

    SET output = CONCAT(output, SUBSTRING(itoa64, ((value >> 6) & 0x3f) + 1, 1));

    IF (i >= count) THEN
      LEAVE myloop;
    END IF;

    SET i = i + 1;

    IF (i < count) THEN
      SET value = value | (ORD(SUBSTRING(input, i + 1, 1)) << 16);
    END IF;

    SET output = CONCAT(output, SUBSTRING(itoa64, ((value >> 12) & 0x3f) + 1, 1));

    IF (i >= count) THEN
      LEAVE myloop;
    END IF;

    SET i = i + 1;

    SET output = CONCAT(output, SUBSTRING(itoa64, ((value >> 18) & 0x3f) + 1, 1));

  END WHILE;

  RETURN output;

END; $$

/**
 * Hash a password using a secure stretched hash.
 *
 * By using a salt and repeated hashing the password is "stretched". Its
 * security is increased because it becomes much more computationally costly
 * for an attacker to try to break the hash by brute-force computation of the
 * hashes of a large number of plain-text words or strings to find a match.
 *
 * @param $password
 *   Plain-text password up to 512 bytes (128 to 512 UTF-8 characters) to hash.
 * @param $setting
 *   An existing hash or the output of _password_generate_salt().  Must be
 *   at least 12 characters (the settings and salt).
 *
 * @return
 *   A string containing the hashed password (and salt) or NULL on failure.
 *   The return string will be truncated at DRUPAL_HASH_LENGTH(55) characters max.
 */
DROP FUNCTION IF EXISTS _password_crypt;
CREATE FUNCTION _password_crypt(
  password VARCHAR(255) CHARACTER SET utf8,
  setting VARCHAR(255) CHARACTER SET utf8
)

RETURNS VARCHAR(255) CHARACTER SET utf8

BEGIN
  DECLARE output, salt VARCHAR(255) CHARACTER SET utf8 DEFAULT '';
  DECLARE count_log2, count INT DEFAULT 0;
  DECLARE hash BLOB;

  IF (CHAR_LENGTH(password) > 512) THEN
    RETURN null;
  END IF;

  SET setting = SUBSTRING(setting, 1, 12);

  IF (SUBSTRING(setting, 1, 1) <> '$' OR SUBSTRING(setting, 3, 1) <> '$') THEN
    RETURN null;
  END IF;

  SET count_log2 = CHAR_LENGTH(SUBSTRING_INDEX(_password_itoa64(), SUBSTRING(setting, 4, 1), 1));

  IF (count_log2 < 7 OR count_log2 > 30) THEN
    RETURN null;
  END IF;

  SET salt = SUBSTRING(setting, 5, 8);
  IF (CHAR_LENGTH(salt) <> 8) THEN
    RETURN null;
  END IF;

  SET count = 1 << count_log2;

  IF (count < 1) THEN
    SET count = 1;
  END IF;

  SET hash = UNHEX(SHA2(CONCAT(salt, password), 512));

  WHILE count > 0 DO
    SET hash = UNHEX(SHA2(CONCAT(hash, password), 512));
    SET count = count - 1;
  END WHILE;

  SET count = CHAR_LENGTH(hash);
  SET output = CONCAT(setting, _password_base64_encode(hash, count));

  SET count = 12 + CEILING((8 * count) / 6);

  IF (CHAR_LENGTH(output) <> count) THEN
    RETURN null;
  END IF;

  SET output = SUBSTRING(output, 1, 55);

  RETURN output;

END; $$

/**
 * Hash a password using a secure hash.
 *
 * @param $password
 *   A plain-text password.
 * @param $count_log2
 *   Optional integer to specify the iteration count. Generally used only during
 *   mass operations where a value less than the default is needed for speed.
 *
 * @return
 *   A string containing the hashed password (and a salt), or NULL on failure.
 */
DROP FUNCTION IF EXISTS drupal_hash_password;
CREATE FUNCTION drupal_hash_password(
  password VARCHAR(255) CHARACTER SET utf8,
  count_log2 INT
)

RETURNS VARCHAR(255) CHARACTER SET utf8

BEGIN
  DECLARE output, salt VARCHAR(255) CHARACTER SET utf8 DEFAULT '';
  SET salt = _password_generate_salt(count_log2);
  SET output = _password_crypt(password, salt);

  RETURN output;

END; $$
