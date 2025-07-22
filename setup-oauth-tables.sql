-- OAuth Client Applications Table
CREATE TABLE IF NOT EXISTS oauth_clients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL, -- Comma-separated list of allowed redirect URIs
    scope VARCHAR(500) DEFAULT 'read',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Authorization Codes Table
CREATE TABLE IF NOT EXISTS authorization_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(255) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(500) NOT NULL,
    scope VARCHAR(500) DEFAULT 'read',
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Sample OAuth Client Registration
INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uri, scope) VALUES 
('my-app-client-id', 'my-app-client-secret-hash', 'My Application', 'http://localhost:3001/auth/callback,https://myapp.com/auth/callback', 'read write'),
('mobile-app-id', 'mobile-app-secret-hash', 'Mobile App', 'myapp://auth/callback', 'read write profile');