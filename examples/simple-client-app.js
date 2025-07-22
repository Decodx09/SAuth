const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch'); // You may need to install: npm install node-fetch

const app = express();
const PORT = 3001;

// Session configuration
app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// OAuth configuration - Update these values
const OAUTH_CONFIG = {
  authUrl: 'http://localhost:3000/api/auth/authorize',
  tokenUrl: 'http://localhost:3000/api/auth/token',
  validateUrl: 'http://localhost:3000/api/auth/validate',
  clientId: 'your-client-id', // Get this from registering your client
  clientSecret: 'your-client-secret', // Get this from registering your client
  redirectUri: 'http://localhost:3001/auth/callback'
};

// Home page
app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Welcome, ${req.session.user.name}!</h1>
      <p>You are logged in via OAuth.</p>
      <p><strong>User Info:</strong></p>
      <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
      <p><a href="/profile">View Profile</a></p>
      <p><a href="/logout">Logout</a></p>
    `);
  } else {
    res.send(`
      <h1>OAuth Client Example</h1>
      <p>This is a demo client application that integrates with your OAuth server.</p>
      <p><a href="/login">Login with OAuth</a></p>
    `);
  }
});

// Initiate OAuth login
app.get('/login', (req, res) => {
  // Generate random state for security
  const state = Math.random().toString(36).substring(7);
  req.session.oauthState = state;
  
  // Build authorization URL
  const authUrl = new URL(OAUTH_CONFIG.authUrl);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', OAUTH_CONFIG.clientId);
  authUrl.searchParams.append('redirect_uri', OAUTH_CONFIG.redirectUri);
  authUrl.searchParams.append('scope', 'read write profile');
  authUrl.searchParams.append('state', state);
  
  console.log('Redirecting to:', authUrl.toString());
  res.redirect(authUrl.toString());
});

// OAuth callback handler
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  // Handle OAuth errors
  if (error) {
    return res.status(400).send(`OAuth Error: ${error}`);
  }
  
  // Verify state parameter to prevent CSRF
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter - possible CSRF attack');
  }
  
  if (!code) {
    return res.status(400).send('No authorization code received');
  }
  
  try {
    console.log('Exchanging code for tokens...');
    
    // Exchange authorization code for access token
    const tokenResponse = await fetch(OAUTH_CONFIG.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        client_id: OAUTH_CONFIG.clientId,
        client_secret: OAUTH_CONFIG.clientSecret,
        redirect_uri: OAUTH_CONFIG.redirectUri
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      console.error('Token exchange failed:', tokenData);
      return res.status(400).send(`Token exchange failed: ${tokenData.error || 'Unknown error'}`);
    }
    
    console.log('Token exchange successful');
    
    // Store tokens and user info in session
    req.session.accessToken = tokenData.access_token;
    req.session.refreshToken = tokenData.refresh_token;
    req.session.user = {
      id: tokenData.user.id,
      email: tokenData.user.email,
      name: `${tokenData.user.firstName} ${tokenData.user.lastName}`,
      role: tokenData.user.role,
      isVerified: tokenData.user.isVerified
    };
    
    // Clear OAuth state
    delete req.session.oauthState;
    
    res.redirect('/');
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('Authentication failed');
  }
});

// Protected profile route
app.get('/profile', async (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect('/login');
  }
  
  try {
    // Validate token with OAuth server
    const validateResponse = await fetch(OAUTH_CONFIG.validateUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${req.session.accessToken}`
      }
    });
    
    if (!validateResponse.ok) {
      // Token is invalid, redirect to login
      delete req.session.accessToken;
      delete req.session.user;
      return res.redirect('/login');
    }
    
    const userData = await validateResponse.json();
    
    res.send(`
      <h1>User Profile</h1>
      <p><strong>Validated User Data from OAuth Server:</strong></p>
      <pre>${JSON.stringify(userData, null, 2)}</pre>
      <p><a href="/">Back to Home</a></p>
    `);
  } catch (error) {
    console.error('Profile validation error:', error);
    res.status(500).send('Failed to validate user');
  }
});

// Logout
app.get('/logout', (req, res) => {
  // Clear session
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
🚀 OAuth Client Example App running on http://localhost:${PORT}

Configuration:
- Auth Server: ${OAUTH_CONFIG.authUrl}
- Client ID: ${OAUTH_CONFIG.clientId}
- Redirect URI: ${OAUTH_CONFIG.redirectUri}

Make sure to:
1. Register this client with your OAuth server
2. Update OAUTH_CONFIG with your actual client credentials
3. Install required dependencies: npm install express express-session node-fetch
  `);
});