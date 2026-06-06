try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.resolve(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    process.loadEnvFile(envPath);
  }
} catch (e) {
  console.warn('Could not load .env file via loadEnvFile:', e.message);
}

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.BACKEND_PORT || process.env.PORT || 29001;
const JWT_SECRET = process.env.JWT_SECRET || 'kbs-cloud-sso-secret-key-12345';

// Database Connection
const dbPath = path.join(__dirname, 'kbs_auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
    initializeTables();
  }
});

function initializeTables() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT,
        display_name TEXT,
        is_google_linked INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // SSO Master Sessions table
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        email TEXT,
        expires_at DATETIME,
        FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
      )
    `);

    // Temporary Authorization Codes table
    db.run(`
      CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        email TEXT,
        client_id TEXT,
        redirect_uri TEXT,
        expires_at DATETIME
      )
    `);
  });
}

// Clean up expired sessions and auth codes periodically
setInterval(() => {
  const now = new Date().toISOString();
  db.run('DELETE FROM sessions WHERE expires_at < ?', [now]);
  db.run('DELETE FROM auth_codes WHERE expires_at < ?', [now]);
}, 5 * 60 * 1000); // Every 5 minutes

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Enable CORS
app.use(cors({
  origin: function(origin, callback) {
    // Allow starswarm, ticker-clash and self
    if (!origin) return callback(null, true);
    const allowed = [
      'http://localhost:8080', 'http://127.0.0.1:8080',
      'http://localhost:8081', 'http://127.0.0.1:8081',
      'http://localhost:8082', 'http://127.0.0.1:8082',
      'http://localhost:19000', 'http://127.0.0.1:19000',
      'http://localhost:19001', 'http://127.0.0.1:19001',
      'http://localhost:19002', 'http://127.0.0.1:19002',
      'http://localhost:19003', 'http://127.0.0.1:19003',
      'http://auth.kbs-cloud.com:8080',
      'http://starswarm.kbs-cloud.com:8081',
      'http://tickerclash.kbs-cloud.com:8082',
      'https://auth.kbs-cloud.com', 'http://auth.kbs-cloud.com',
      'https://starswarm.kbs-cloud.com', 'http://starswarm.kbs-cloud.com',
      'https://tickerclash.kbs-cloud.com', 'http://tickerclash.kbs-cloud.com',
      'https://ticker-clash.kbs-cloud.com', 'http://ticker-clash.kbs-cloud.com'
    ];
    if (allowed.indexOf(origin) !== -1 || origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
      return callback(null, true);
    }
    callback(null, true);
  },
  credentials: true
}));

// Google Client setup
const getGoogleClient = (req) => {
  let callbackUrl = 'https://auth.kbs-cloud.com/api/auth/callback/google';
  
  if (req) {
    const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    if (proto === 'https') {
      callbackUrl = 'https://auth.kbs-cloud.com/api/auth/callback/google';
    } else if (host) {
      callbackUrl = `http://${host}/api/auth/callback/google`;
    }
  } else if (process.env.GOOGLE_CALLBACK_URL && !process.env.GOOGLE_CALLBACK_URL.includes('star-swarm') && !process.env.GOOGLE_CALLBACK_URL.includes('starswarm')) {
    callbackUrl = process.env.GOOGLE_CALLBACK_URL;
  }

  return new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl
  );
};

// Helper: validate SSO session
function getSSOSessionUser(req, callback) {
  const sessionId = req.cookies['sso_session_id'];
  if (!sessionId) {
    return callback(null, null);
  }
  const now = new Date().toISOString();
  db.get(
    `SELECT u.email, u.display_name, u.is_google_linked, (u.password_hash IS NOT NULL) AS has_password 
     FROM sessions s 
     JOIN users u ON s.email = u.email 
     WHERE s.id = ? AND s.expires_at > ?`,
    [sessionId, now],
    (err, row) => {
      if (err || !row) {
        return callback(null, null);
      }
      callback(null, row);
    }
  );
}

// Generate single-use authorization code
function createAuthCode(email, clientId, redirectUri, callback) {
  const code = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes validity
  db.run(
    'INSERT INTO auth_codes (code, email, client_id, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?)',
    [code, email, clientId, redirectUri, expiresAt],
    (err) => {
      if (err) return callback(err);
      callback(null, code);
    }
  );
}

// 1. Authorize Endpoint (Standard SSO Entrypoint)
app.get('/api/auth/authorize', (req, res) => {
  const { client_id, redirect_uri } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send('Missing client_id or redirect_uri parameters.');
  }

  getSSOSessionUser(req, (err, user) => {
    if (err || !user) {
      // Not logged in. Redirect to SSO Portal Login screen with redirect context
      const loginUrl = `/?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`;
      return res.redirect(loginUrl);
    }

    // Already logged in! Generate authorization code and redirect back instantly
    createAuthCode(user.email, client_id, redirect_uri, (codeErr, code) => {
      if (codeErr) {
        return res.status(500).send('Internal database error creating login code.');
      }
      const separator = redirect_uri.includes('?') ? '&' : '?';
      res.redirect(`${redirect_uri}${separator}code=${code}`);
    });
  });
});

// 2. Token Exchange Endpoint (Game Servers invoke this backend-to-backend)
app.post('/api/auth/token', (req, res) => {
  const { code, client_id } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code.' });
  }

  const now = new Date().toISOString();
  db.get(
    'SELECT * FROM auth_codes WHERE code = ? AND expires_at > ?',
    [code, now],
    (err, authCodeRow) => {
      if (err || !authCodeRow) {
        return res.status(400).json({ error: 'Invalid or expired authorization code.' });
      }

      // Single-use enforcement: delete the code immediately
      db.run('DELETE FROM auth_codes WHERE code = ?', [code]);

      if (client_id && authCodeRow.client_id !== client_id) {
        return res.status(400).json({ error: 'Client ID mismatch.' });
      }

      db.get('SELECT * FROM users WHERE email = ?', [authCodeRow.email], (userErr, user) => {
        if (userErr || !user) {
          return res.status(400).json({ error: 'User associated with code not found.' });
        }

        // Generate signed JWT token containing user identity
        const tokenPayload = {
          email: user.email,
          displayName: user.display_name || null,
          isGoogleLinked: user.is_google_linked === 1
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
          success: true,
          token,
          user: tokenPayload
        });
      });
    }
  );
});

// 3. Central Login
app.post('/api/auth/login', (req, res) => {
  const { email, password, client_id, redirect_uri } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please enter email and password.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  db.get('SELECT * FROM users WHERE email = ?', [normalizedEmail], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: 'Account not found. Please register.' });
    }

    if (!user.password_hash) {
      return res.status(400).json({
        error: 'This account uses Google Sign-in. Please log in using Google.'
      });
    }

    const isMatch = bcrypt.compareSync(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    // Initialize SSO master session
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours SSO session

    db.run(
      'INSERT INTO sessions (id, email, expires_at) VALUES (?, ?, ?)',
      [sessionId, normalizedEmail, expiresAt],
      (sessionErr) => {
        if (sessionErr) {
          return res.status(500).json({ error: 'Failed to create active session.' });
        }

        // Set HttpOnly Cookie scoped for SSO domain
        res.cookie('sso_session_id', sessionId, {
          httpOnly: true,
          path: '/',
          sameSite: 'lax',
          secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        const responseData = {
          success: true,
          user: {
            email: user.email,
            displayName: user.display_name || null,
            isGoogleLinked: user.is_google_linked === 1,
            hasPassword: !!user.password_hash
          }
        };

        // If authorization parameters exist, generate redirect URI with code
        if (client_id && redirect_uri) {
          createAuthCode(user.email, client_id, redirect_uri, (codeErr, code) => {
            if (codeErr) {
              return res.status(500).json({ error: 'Failed to create login redirect code.' });
            }
            const separator = redirect_uri.includes('?') ? '&' : '?';
            responseData.redirectUri = `${redirect_uri}${separator}code=${code}`;
            res.status(200).json(responseData);
          });
        } else {
          res.status(200).json(responseData);
        }
      }
    );
  });
});

// 4. Central Registration
app.post('/api/auth/register', (req, res) => {
  const { email, password, displayName } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = bcrypt.hashSync(password, 10);

  db.run(
    'INSERT INTO users (email, password_hash, display_name, is_google_linked) VALUES (?, ?, ?, 0)',
    [normalizedEmail, passwordHash, displayName || null],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'An account with this email already exists.' });
        }
        return res.status(500).json({ error: 'Database registration error.' });
      }
      res.status(201).json({ success: true, message: 'Account registered successfully.' });
    }
  );
});

// 5. Get current SSO User Details
app.get('/api/auth/me', (req, res) => {
  getSSOSessionUser(req, (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Unauthorized. No active SSO session.' });
    }
    res.status(200).json({
      success: true,
      user: {
        email: user.email,
        displayName: user.display_name,
        isGoogleLinked: user.is_google_linked === 1,
        hasPassword: user.has_password === 1
      }
    });
  });
});

// 5.1 Change/Set Password
app.post('/api/auth/change-password', (req, res) => {
  getSSOSessionUser(req, (err, sessionUser) => {
    if (err || !sessionUser) {
      return res.status(401).json({ error: 'Unauthorized. No active SSO session.' });
    }

    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    // Retrieve user details from database to check for existing password_hash
    db.get('SELECT password_hash FROM users WHERE email = ?', [sessionUser.email], (userErr, user) => {
      if (userErr || !user) {
        return res.status(500).json({ error: 'User details not found.' });
      }

      // If they already have a password set, they must provide their correct current password
      if (user.password_hash) {
        if (!currentPassword) {
          return res.status(400).json({ error: 'Please enter your current password.' });
        }
        const isMatch = bcrypt.compareSync(currentPassword, user.password_hash);
        if (!isMatch) {
          return res.status(400).json({ error: 'Incorrect current password.' });
        }
      }

      // Hash and update the password
      const newHash = bcrypt.hashSync(newPassword, 10);
      db.run('UPDATE users SET password_hash = ? WHERE email = ?', [newHash, sessionUser.email], (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: 'Failed to update password.' });
        }
        res.status(200).json({ success: true, message: 'Password updated successfully.' });
      });
    });
  });
});

// 6. Central Logout
app.all('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies['sso_session_id'];
  if (sessionId) {
    db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
  }
  res.clearCookie('sso_session_id', {
    path: '/',
    sameSite: 'lax',
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  });

  const redirectUri = req.query.redirect_uri || req.body.redirect_uri;
  if (redirectUri) {
    return res.redirect(redirectUri);
  }

  res.status(200).json({ success: true, message: 'Logged out from all systems.' });
});

// 7. Google OAuth Login redirection (supports client flow)
app.get('/api/auth/google', (req, res) => {
  const { client_id, redirect_uri } = req.query;

  // Preserve redirect context inside the state param
  const stateObj = { client_id, redirect_uri };
  const stateStr = Buffer.from(JSON.stringify(stateObj)).toString('base64');

  const client = getGoogleClient(req);
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.email', 'profile'],
    state: stateStr
  });
  res.redirect(url);
});

// 8. Google OAuth Callback
app.get('/api/auth/callback/google', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('Google OAuth Callback error parameter:', error);
    return res.redirect(`/?error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    console.error('Google OAuth Callback missing code parameter');
    return res.redirect('/?error=missing_code');
  }

  let stateObj = {};
  try {
    if (state) {
      stateObj = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
    }
  } catch (err) {
    console.error('Failed to parse state parameter:', err);
  }

  const { client_id, redirect_uri } = stateObj;

  try {
    const client = getGoogleClient(req);
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();
    const displayName = payload.name;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      const handleSessionCreation = (finalUserEmail, finalDisplayName) => {
        const sessionId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        db.run(
          'INSERT INTO sessions (id, email, expires_at) VALUES (?, ?, ?)',
          [sessionId, finalUserEmail, expiresAt],
          (sessErr) => {
            if (sessErr) {
              return res.status(500).send('Session creation failed.');
            }

            res.cookie('sso_session_id', sessionId, {
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
              maxAge: 24 * 60 * 60 * 1000
            });

            if (client_id && redirect_uri) {
              createAuthCode(finalUserEmail, client_id, redirect_uri, (codeErr, code) => {
                if (codeErr) return res.status(500).send('Auth code creation failed.');
                const separator = redirect_uri.includes('?') ? '&' : '?';
                res.redirect(`${redirect_uri}${separator}code=${code}`);
              });
            } else {
              res.redirect('/');
            }
          }
        );
      };

      if (user) {
        if (user.is_google_linked === 0) {
          db.run('UPDATE users SET is_google_linked = 1 WHERE email = ?', [email]);
        }
        handleSessionCreation(user.email, user.display_name || displayName);
      } else {
        db.run(
          'INSERT INTO users (email, password_hash, is_google_linked, display_name) VALUES (?, NULL, 1, ?)',
          [email, displayName],
          function (insertErr) {
            if (insertErr) {
              return res.status(500).send('User registration failed.');
            }
            handleSessionCreation(email, displayName);
          }
        );
      }
    });
  } catch (error) {
    console.error('Google OAuth Error:', error);
    res.redirect('/?error=oauth_failed');
  }
});

// Serves the client SPA files in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*splat', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`KBS-Auth service running on port ${PORT}`);
});

if (process.env.FRONTEND_PORT && String(process.env.FRONTEND_PORT) !== String(PORT)) {
  const frontendApp = express();
  const http = require('http');

  // Proxy API requests to the backend server
  frontendApp.all('/api/*splat', (req, res) => {
    const connector = http.request({
      host: 'localhost',
      port: PORT,
      path: req.originalUrl,
      method: req.method,
      headers: req.headers
    }, (connectorRes) => {
      res.writeHead(connectorRes.statusCode, connectorRes.headers);
      connectorRes.pipe(res);
    });

    req.pipe(connector);

    connector.on('error', (err) => {
      console.error('Auth frontend proxy error:', err);
      res.status(502).send('Bad Gateway');
    });
  });

  frontendApp.use(express.static(path.join(__dirname, 'dist')));
  frontendApp.get('*splat', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });
  frontendApp.listen(process.env.FRONTEND_PORT, () => {
    console.log(`KBS-Auth static frontend server running on port ${process.env.FRONTEND_PORT}`);
  });
}
