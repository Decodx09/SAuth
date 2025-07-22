# OAuth Integration Guide

This guide shows how to integrate your OAuth provider with other applications.

## Overview

Your system acts as an **OAuth 2.0 Authorization Server**. Other applications (clients) can use it for authentication and authorization.

## 1. Setup OAuth Tables

Run the SQL script to create necessary tables:
```bash
mysql -u your_username -p your_database < setup-oauth-tables.sql
```

## 2. Register Client Applications

For each application that wants to integrate:

```javascript
// Example: Register a new client application
const crypto = require('crypto');

const clientData = {
  client_id: 'unique-client-id',
  client_secret: crypto.randomBytes(32).toString('hex'),
  name: 'My Web Application',
  redirect_uri: 'https://myapp.com/auth/callback,http://localhost:3001/auth/callback',
  scope: 'read write profile'
};

// Insert into database
await pool.execute(
  "INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uri, scope) VALUES (?, ?, ?, ?, ?)",
  [clientData.client_id, clientData.client_secret, clientData.name, clientData.redirect_uri, clientData.scope]
);
```

## 3. OAuth Flow Implementation

### Step 1: Authorization Request
Client redirects user to your authorization endpoint:

```
GET /api/auth/authorize?
  response_type=code&
  client_id=your-client-id&
  redirect_uri=https://myapp.com/auth/callback&
  scope=read write&
  state=random-state-string
```

### Step 2: User Authentication
- User logs in through your system
- User grants permission to the client application
- System generates authorization code

### Step 3: Token Exchange
Client exchanges authorization code for access token:

```javascript
// POST /api/auth/token
const tokenResponse = await fetch('http://your-auth-server.com/api/auth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: 'received-auth-code',
    client_id: 'your-client-id',
    client_secret: 'your-client-secret',
    redirect_uri: 'https://myapp.com/auth/callback'
  })
});

const tokens = await tokenResponse.json();
// Returns: { access_token, refresh_token, token_type, expires_in, user }
```

## 4. Client Application Examples

### Web Application (Node.js/Express)

```javascript
const express = require('express');
const app = express();

// OAuth configuration
const OAUTH_CONFIG = {
  authUrl: 'http://your-auth-server.com/api/auth/authorize',
  tokenUrl: 'http://your-auth-server.com/api/auth/token',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:3001/auth/callback'
};

// Step 1: Redirect to authorization server
app.get('/login', (req, res) => {
  const state = Math.random().toString(36).substring(7);
  req.session.oauthState = state;
  
  const authUrl = new URL(OAUTH_CONFIG.authUrl);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', OAUTH_CONFIG.clientId);
  authUrl.searchParams.append('redirect_uri', OAUTH_CONFIG.redirectUri);
  authUrl.searchParams.append('scope', 'read write profile');
  authUrl.searchParams.append('state', state);
  
  res.redirect(authUrl.toString());
});

// Step 2: Handle callback
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // Verify state parameter
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter');
  }
  
  try {
    // Exchange code for tokens
    const tokenResponse = await fetch(OAUTH_CONFIG.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: OAUTH_CONFIG.clientId,
        client_secret: OAUTH_CONFIG.clientSecret,
        redirect_uri: OAUTH_CONFIG.redirectUri
      })
    });
    
    const tokens = await tokenResponse.json();
    
    // Store tokens securely
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;
    req.session.user = tokens.user;
    
    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).send('Authentication failed');
  }
});

// Protected route
app.get('/dashboard', (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect('/login');
  }
  
  res.json({
    message: 'Welcome to dashboard',
    user: req.session.user
  });
});
```

### React Application

```javascript
// OAuth service
class OAuthService {
  constructor() {
    this.config = {
      authUrl: 'http://your-auth-server.com/api/auth/authorize',
      tokenUrl: 'http://your-auth-server.com/api/auth/token',
      clientId: 'your-client-id',
      redirectUri: 'http://localhost:3000/auth/callback'
    };
  }
  
  // Initiate OAuth flow
  login() {
    const state = Math.random().toString(36).substring(7);
    localStorage.setItem('oauthState', state);
    
    const authUrl = new URL(this.config.authUrl);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', this.config.clientId);
    authUrl.searchParams.append('redirect_uri', this.config.redirectUri);
    authUrl.searchParams.append('scope', 'read write profile');
    authUrl.searchParams.append('state', state);
    
    window.location.href = authUrl.toString();
  }
  
  // Handle callback
  async handleCallback(code, state) {
    const storedState = localStorage.getItem('oauthState');
    if (state !== storedState) {
      throw new Error('Invalid state parameter');
    }
    
    const response = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: this.config.clientId,
        redirect_uri: this.config.redirectUri
      })
    });
    
    const tokens = await response.json();
    
    // Store tokens
    localStorage.setItem('accessToken', tokens.access_token);
    localStorage.setItem('refreshToken', tokens.refresh_token);
    localStorage.setItem('user', JSON.stringify(tokens.user));
    
    return tokens;
  }
  
  // Make authenticated requests
  async apiCall(url, options = {}) {
    const token = localStorage.getItem('accessToken');
    
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });
  }
}
```

### Mobile App (React Native)

```javascript
import { authorize, refresh } from 'react-native-app-auth';

const config = {
  issuer: 'http://your-auth-server.com',
  clientId: 'your-mobile-client-id',
  redirectUrl: 'com.yourapp://oauth/callback',
  scopes: ['read', 'write', 'profile'],
  additionalParameters: {},
  customHeaders: {}
};

// Login
const login = async () => {
  try {
    const result = await authorize(config);
    // Store tokens securely
    await AsyncStorage.setItem('accessToken', result.accessToken);
    await AsyncStorage.setItem('refreshToken', result.refreshToken);
  } catch (error) {
    console.error('Login failed', error);
  }
};
```

## 5. Token Validation

Other applications can validate tokens using your introspection endpoint:

```javascript
// Validate token
const validateToken = async (token) => {
  const response = await fetch('http://your-auth-server.com/api/auth/introspect', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Basic ${Buffer.from('client_id:client_secret').toString('base64')}`
    },
    body: JSON.stringify({ token })
  });
  
  const result = await response.json();
  return result.active;
};
```

## 6. Environment Configuration

Update your `.env` file:

```env
# OAuth Configuration
JWT_SECRET=your-jwt-secret
REFRESH_TOKEN_SECRET=your-refresh-token-secret
FRONTEND_URL=http://localhost:3000

# Database
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
```

## 7. Security Best Practices

1. **Use HTTPS in production**
2. **Validate redirect URIs strictly**
3. **Implement proper CORS policies**
4. **Use secure, random client secrets**
5. **Implement rate limiting**
6. **Log all OAuth activities**
7. **Regularly rotate secrets**

## 8. Testing OAuth Integration

```bash
# Test authorization endpoint
curl "http://localhost:3000/api/auth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3001/callback&state=test123"

# Test token exchange
curl -X POST http://localhost:3000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "your-auth-code",
    "client_id": "test-client",
    "client_secret": "test-secret",
    "redirect_uri": "http://localhost:3001/callback"
  }'

# Test token validation
curl -X POST http://localhost:3000/api/auth/introspect \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"token": "your-access-token"}'
```

## 9. Common Integration Patterns

### Single Sign-On (SSO)
- Users log in once to your auth server
- Access multiple applications without re-authentication

### API Gateway Integration
- Use your OAuth server with API gateways
- Centralized authentication for microservices

### Third-party Service Integration
- Allow external services to access your APIs
- Controlled access through OAuth scopes

This setup allows any application to integrate with your OAuth provider for secure authentication and authorization.