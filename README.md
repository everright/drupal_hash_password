# drupal_hash_password
Ported the function user_hash_password of Drupal to MySQL.

Requirements
------------

* MySQL 5.5.6+

Support
-------

* Drupal 7
* Drupal 8

Install
-------

Import the SQL file with drush. 

    $ drush sqlq --file=drupal_hash_password/drupal_hash_password.sql

Usage
-----

Drupal password hash

    mysql> select drupal_hash_password('Your Password', 15);

Update user's password with plain-text.

    mysql> UPDATE users SET pass = drupal_hash_password('Your Password', 15) WHERE uid = 1;

Update user's password with md5 hashed.

    mysql> UPDATE users SET pass = CONCAT('U', drupal_hash_password('Your MD5 Hashed Password', 11)) WHERE uid = 1;