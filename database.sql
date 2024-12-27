

-- Create the database
CREATE DATABASE IF NOT EXISTS user_auth_system;
USE user_auth_system;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    mobile VARCHAR(10) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    auth_provider ENUM('local', 'google', 'facebook', 'apple') DEFAULT 'local',
    auth_provider_id VARCHAR(255),
    created_date DATETIME NOT NULL,
    created_by VARCHAR(50) NOT NULL,
    updated_date DATETIME,
    updated_by VARCHAR(50),
    UNIQUE KEY unique_mobile (mobile),
    UNIQUE KEY unique_provider_id (auth_provider, auth_provider_id)
);

-- Create authentication_logs table
CREATE TABLE authentication_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_date DATETIME NOT NULL,
    created_by VARCHAR(50) NOT NULL,
    updated_date DATETIME,
    updated_by VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id)
);



DELIMITER //

-- Create user procedure
CREATE PROCEDURE sp_CreateUser(
    IN p_first_name VARCHAR(50),
    IN p_last_name VARCHAR(50),
    IN p_mobile VARCHAR(10),
    IN p_password VARCHAR(255)
)
BEGIN
    INSERT INTO users (first_name, last_name, mobile, password, created_date)
    VALUES (p_first_name, p_last_name, p_mobile, p_password, CURRENT_TIMESTAMP);
    SELECT LAST_INSERT_ID() as user_id;
END //

-- Get all users procedure
CREATE PROCEDURE sp_GetAllUsers()
BEGIN
    SELECT id, first_name, last_name, mobile, created_date
    FROM users;
END //

-- Get user by ID procedure
CREATE PROCEDURE sp_GetUserById(
    IN p_id INT
)
BEGIN
    SELECT id, first_name, last_name, mobile, created_date
    FROM users
    WHERE id = p_id;
END //

-- Update user procedure
CREATE PROCEDURE sp_UpdateUser(
    IN p_id INT,
    IN p_first_name VARCHAR(50),
    IN p_last_name VARCHAR(50),
    IN p_mobile VARCHAR(10)
)
BEGIN
    UPDATE users
    SET first_name = p_first_name,
        last_name = p_last_name,
        mobile = p_mobile
    WHERE id = p_id;
    
    SELECT ROW_COUNT() as updated_rows;
END //

-- Delete user procedure
CREATE PROCEDURE sp_DeleteUser(
    IN p_id INT
)
BEGIN
    DELETE FROM users
    WHERE id = p_id;
    
    SELECT ROW_COUNT() as deleted_rows;
END //

DELIMITER ;