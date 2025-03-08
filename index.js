// server.js

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {Web3} = require('web3');

const app = express();
app.use(express.json());

// Database connection parameters from .env
const pool = new Pool({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false }
});

// Secret key for JWT
const SECRET_KEY = process.env.SECRET_KEY || "MPC";

// Logger
const logger = console;

// ---------------------------------------------------------------------------
// Helper Functions for Shamir's Secret Sharing using BigInt
// ---------------------------------------------------------------------------
function stringToInt(input_secret) {
  if (typeof input_secret === 'string') {
    if (input_secret.startsWith('0x')) {
      return BigInt(input_secret);
    } else if (/^\d+$/.test(input_secret)) {
      return BigInt(input_secret);
    } else {
      return BigInt('0x' + Buffer.from(input_secret, 'utf8').toString('hex'));
    }
  } else if (Buffer.isBuffer(input_secret)) {
    return BigInt('0x' + input_secret.toString('hex'));
  } else {
    throw new Error("Unsupported type for input_secret");
  }
}

function generateRandomPolynomial(secret, degree, prime) {
  const coefficients = [secret % prime];
  for (let i = 0; i < degree; i++) {
    const randBytes = crypto.randomBytes(32);
    const randNum = BigInt('0x' + randBytes.toString('hex')) % prime;
    coefficients.push(randNum);
  }
  return coefficients;
}

function evaluatePolynomial(coefficients, x, prime) {
  let result = BigInt(0);
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = (result * BigInt(x) + coefficients[i]) % prime;
  }
  return result;
}

function generateShares(secret, n_shares, threshold) {
  if (threshold > n_shares) throw new Error("Threshold cannot be greater than total shares");
  const prime = (BigInt(2) ** BigInt(256)) - BigInt(189);
  const secretInt = stringToInt(secret);
  const coefficients = generateRandomPolynomial(secretInt, threshold - 1, prime);
  const shares = [];
  for (let x = 1; x <= n_shares; x++) {
    const y = evaluatePolynomial(coefficients, x, prime);
    shares.push({ x, y: y.toString() });
  }
  return shares;
}

function keyConstruction(shares) {
  if (shares.length < 4) throw new Error("At least 4 shares are required for key construction");
  const user_key = `${shares[0].y.length.toString().padStart(2, '0')}${shares[0].y}${shares[2].y}`;
  const backend_share = `${shares[1].y.length.toString().padStart(2, '0')}${shares[1].y}${shares[3].y}`;
  return { user_key, backend_share };
}

// ---------------------------------------------------------------------------
// Ethereum Wallet Generation using web3
// ---------------------------------------------------------------------------
function generateEthereumWallet() {
  const privateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const web3 = new Web3();
  const account = web3.eth.accounts.privateKeyToAccount(privateKey);
  logger.info(`Generated Private Key: ${privateKey}`);
  return { private_key: privateKey, public_address: account.address };
}

// ---------------------------------------------------------------------------
// JWT Generation
// ---------------------------------------------------------------------------
function generateJwtToken(unique_identifier, user_id, expiry_hours) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    unique_identifier,
    user_id,
    iat: now,
    exp: now + expiry_hours * 3600
  };
  return jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256' });
}

// ---------------------------------------------------------------------------
// Encryption Helpers using crypto (AES-256-GCM)
// ---------------------------------------------------------------------------
function generateKeyFromPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return { key, salt: salt.toString('hex') };
}

function encryptShare(share, password) {
  const { key, salt } = generateKeyFromPassword(password);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(share, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return { encrypted_share: `${iv.toString('hex')}:${tag}:${encrypted}`, salt };
}

// ---------------------------------------------------------------------------
// Database Helper: Check if user exists
// ---------------------------------------------------------------------------
async function checkUserExists(unique_identifier) {
  try {
    const result = await pool.query(
      `SELECT user_id, device_info FROM users WHERE LOWER(unique_identifier) = LOWER($1)`,
      [unique_identifier]
    );
    if (result.rows.length > 0) {
      logger.info(`User found: user_id=${result.rows[0].user_id}, device_info=${result.rows[0].device_info}`);
      return result.rows[0];
    } else {
      logger.info("User does not exist.");
      return null;
    }
  } catch (error) {
    logger.error(`Error checking user existence: ${error.message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Generate Referral Code
// ---------------------------------------------------------------------------
function generateReferralCode(user_id) {
  const hash = crypto.createHash('sha256').update(String(user_id)).digest('hex');
  const referral_suffix = hash.slice(0, 5).toUpperCase();
  return `MPC${referral_suffix}`;
}

// ---------------------------------------------------------------------------
// Compare device_info
// ---------------------------------------------------------------------------
function compareDeviceInfo(input, stored) {
  return input === stored;
}

// ---------------------------------------------------------------------------
// Express Routes
// ---------------------------------------------------------------------------

// POST /user: Create User
app.post('/user', async (req, res) => {
  try {
    const body = req.body;
    const unique_identifier = (body.unique_identifier || "").trim().toLowerCase();
    const username = body.username;
    const org_id = body.org_id;
    const method = body.method;
    const secure = body.secure || false;
    const password = body.password;
    let device_info = body.device_info;
    const expiry_hours = body.expiry_hours || 24;

    logger.info(`Received request to create user: ${unique_identifier}`);

    if (!unique_identifier) {
      return res.status(400).json({ message: "unique_identifier is required" });
    }
    if (secure && !password) {
      return res.status(400).json({ message: "Password is required when secure is TRUE" });
    }
    if (secure) {
      const word_count = password.trim().split(/\s+/).length;
      if (word_count !== 12) {
        return res.status(400).json({ message: "Password must be twelve words" });
      }
    }

    // Attempt to parse device_info if it is a string
    try {
      device_info = JSON.parse(device_info);
    } catch (err) {
      // leave as is if parsing fails
    }

    const existingUser = await checkUserExists(unique_identifier);
    if (existingUser) {
      const user_id = existingUser.user_id;
      const device_valid = compareDeviceInfo(body.device_info, existingUser.device_info);
      const shareResult = await pool.query(
        `SELECT encrypted_user_share, salt, secure FROM mpc_users_share WHERE unique_id = $1`,
        [user_id]
      );
      let encrypted_user_share, salt, secure_status;
      if (shareResult.rows.length > 0) {
        ({ encrypted_user_share, salt, secure: secure_status } = shareResult.rows[0]);
        logger.info("Fetched existing shares.");
      } else {
        encrypted_user_share = null;
        salt = null;
        secure_status = false;
        logger.warn("No shares found for the user.");
      }
      const jwt_token = generateJwtToken(unique_identifier, user_id, expiry_hours);
      await pool.query(`UPDATE users SET jwt_token = $1 WHERE user_id = $2`, [jwt_token, user_id]);
      return res.status(200).json({
        message: "User exists",
        device_valid,
        user_share: encrypted_user_share,
        salt,
        secure: secure_status,
        user_id,
        jwt_token
      });
    }

    // Create new user if not exists
    const wallet = generateEthereumWallet();
    const shares = generateShares(wallet.private_key, 4, 3);
    const { user_key, backend_share } = keyConstruction(shares);

    const created_at = new Date();
    const insertUserQuery = `
      INSERT INTO users (unique_identifier, username, org_id, method, device_info, created_at, user_public_wallet, backend_share)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING user_id
    `;
    const userResult = await pool.query(insertUserQuery, [
      unique_identifier,
      username,
      org_id,
      method,
      JSON.stringify(device_info),
      created_at,
      wallet.public_address,
      backend_share
    ]);
    const user_id = userResult.rows[0].user_id;
    logger.info(`Created new user with user_id: ${user_id}`);

    const referral_code = generateReferralCode(user_id);
    await pool.query(`UPDATE users SET referral_code = $1 WHERE user_id = $2`, [referral_code, user_id]);
    const jwt_token = generateJwtToken(unique_identifier, user_id, expiry_hours);
    await pool.query(`UPDATE users SET jwt_token = $1 WHERE user_id = $2`, [jwt_token, user_id]);

    let encrypted_share, saltValue;
    if (secure) {
      const encryptedData = encryptShare(user_key, password);
      encrypted_share = encryptedData.encrypted_share;
      saltValue = encryptedData.salt;
      logger.info("Encrypted user_share with password.");
    } else {
      encrypted_share = user_key;
      saltValue = null;
      logger.info("User is not secured. Using plain user_key.");
    }

    await pool.query(
      `INSERT INTO mpc_users_share (unique_id, encrypted_user_share, salt, secure, count_words)
       VALUES ($1, $2, $3, $4, $5)`,
      [user_id, encrypted_share, saltValue, secure, secure ? password.trim().split(/\s+/).length : 0]
    );

    // No external API call; shares are stored in the database

    return res.status(200).json({
      user_id,
      jwt_token,
      referral_code,
      user_share: encrypted_share,
      ...(secure && { user_key })
    });
  } catch (error) {
    logger.error(`Error in create user: ${error.message}`);
    return res.status(500).json({ message: error.message });
  }
});

// GET /user: Fetch User(s)
app.get('/user', async (req, res) => {
  const { fetch, user_id, UID } = req.query;
  try {
    if (fetch === "all") {
      logger.info("Fetching total_count, google_users, and metamask_users from the users table...");
      const totalRes = await pool.query("SELECT COUNT(*) FROM users");
      const googleRes = await pool.query("SELECT COUNT(*) FROM users WHERE LOWER(method) = 'email'");
      const metamaskRes = await pool.query("SELECT COUNT(*) FROM users WHERE method IS NULL OR LOWER(method) = 'metamask'");
      return res.status(200).json({
        total_count: totalRes.rows[0].count,
        google_users: googleRes.rows[0].count,
        metamask_users: metamaskRes.rows[0].count
      });
    }

    let userData;
    if (UID) {
      logger.info(`Fetching user by unique_identifier: ${UID}`);
      const userRes = await pool.query(`SELECT * FROM users WHERE LOWER(unique_identifier) = LOWER($1)`, [UID]);
      if (userRes.rows.length === 0) return res.status(404).json({ message: "User not found" });
      userData = userRes.rows[0];
    } else if (user_id) {
      logger.info(`Fetching user by user_id: ${user_id}`);
      const userRes = await pool.query(`SELECT * FROM users WHERE user_id = $1`, [user_id]);
      if (userRes.rows.length === 0) return res.status(404).json({ message: "User not found" });
      userData = userRes.rows[0];
    } else {
      return res.status(400).json({ message: "Provide either fetch=all, user_id, or UID" });
    }

    // Rename keys if needed
    if (userData.user_public_wallet) {
      userData.user_public_address = userData.user_public_wallet;
      delete userData.user_public_wallet;
    }

    // Fetch secure status from mpc_users_share
    const shareRes = await pool.query(`SELECT secure FROM mpc_users_share WHERE unique_id = $1`, [userData.user_id]);
    userData.secure = shareRes.rows.length > 0 ? shareRes.rows[0].secure : false;

    return res.status(200).json(userData);
  } catch (error) {
    logger.error(`Error fetching user: ${error.message}`);
    return res.status(500).json({ message: error.message });
  }
});

// PUT /user: Update User
app.put('/user', async (req, res) => {
  const body = req.body;
  const user_id = body.user_id;
  const action = body.action;
  const username = body.username;
  const secure = body.secure;
  const password = body.password;

  if (!user_id) {
    return res.status(400).json({ message: "user_id is required" });
  }
  try {
    const shareRes = await pool.query(`SELECT secure FROM mpc_users_share WHERE unique_id = $1`, [user_id]);
    if (shareRes.rows.length === 0) {
      return res.status(404).json({ message: "User share not found" });
    }
    const current_secure = shareRes.rows[0].secure;

    if (secure !== undefined) {
      if (typeof secure !== "boolean") {
        return res.status(400).json({ message: "secure must be a boolean (true or false)" });
      }
      if (secure && !current_secure) {
        if (!password) {
          return res.status(400).json({ message: "Password is required to secure the account" });
        }
        const word_count = password.trim().split(/\s+/).length;
        if (word_count !== 12) {
          return res.status(400).json({ message: "Password must be twelve words" });
        }
        const existingShareRes = await pool.query(`SELECT encrypted_user_share FROM mpc_users_share WHERE unique_id = $1`, [user_id]);
        if (existingShareRes.rows.length === 0) {
          return res.status(404).json({ message: "User share not found" });
        }
        const existing_share = existingShareRes.rows[0].encrypted_user_share;
        const encryptedData = encryptShare(existing_share, password);
        const count_words = password.trim().split(/\s+/).length;
        await pool.query(
          `UPDATE mpc_users_share SET encrypted_user_share = $1, salt = $2, secure = $3, count_words = $4 WHERE unique_id = $5`,
          [encryptedData.encrypted_share, encryptedData.salt, secure, count_words, user_id]
        );
      } else if (!secure && current_secure) {
        return res.status(400).json({ message: "Unsecuring the account is not supported" });
      }
    }

    if (action === "all") {
      const skip_keys = ["user_id", "action", "secure", "password"];
      const updates = [];
      const params = [];
      let idx = 1;
      for (const key in body) {
        if (!skip_keys.includes(key)) {
          updates.push(`${key} = $${idx}`);
          params.push(body[key]);
          idx++;
        }
      }
      params.push(user_id);
      if (updates.length > 0) {
        const updateQuery = `UPDATE users SET ${updates.join(", ")} WHERE user_id = $${idx}`;
        await pool.query(updateQuery, params);
      }
    } else {
      if (username) {
        await pool.query(`UPDATE users SET username = $1 WHERE user_id = $2`, [username, user_id]);
      }
    }

    return res.status(200).json({ message: "User updated" });
  } catch (error) {
    logger.error(`Error updating user: ${error.message}`);
    return res.status(500).json({ message: error.message });
  }
});

// DELETE /user: Delete User
app.delete('/user', async (req, res) => {
  const { user_id } = req.query;
  if (!user_id) {
    return res.status(400).json({ message: "user_id is required" });
  }
  try {
    await pool.query(`DELETE FROM mpc_users_share WHERE unique_id = $1`, [user_id]);
    await pool.query(`DELETE FROM users WHERE user_id = $1`, [user_id]);
    return res.status(200).json({ message: "User deleted" });
  } catch (error) {
    logger.error(`Error deleting user: ${error.message}`);
    return res.status(500).json({ message: error.message });
  }
});

// ---------------------------------------------------------------------------
// Start Express Server on Port 6000
// ---------------------------------------------------------------------------
app.listen(process.env.PORT || 6000, () => {
  console.log("Express server running on port 6000");
});
