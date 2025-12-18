const express = require('express');
const { Pool } = require('pg');
const helmet = require('helmet'); // Mandatory for SOC2/Security
const morgan = require('morgan'); // Professional logging
const AWSXRay = require('aws-xray-sdk'); // Distributed tracing

const app = express();
const port = process.env.PORT || 3000;

// 1. Security & Logging Middleware
app.use(helmet()); 
app.use(morgan('combined'));
app.use(AWSXRay.express.openSegment('EnterpriseApp'));

// 2. Database Connection (Using a Pool, not a Client)
// RUTHLESS NOTE: In production, single 'Clients' crash. 'Pools' scale.
const pool = new Pool({
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // Injected via ECS/Secrets Manager
  port: 5432,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// 3. Application Routes
app.get('/', async (req, res) => {
  try {
    const dbCheck = await pool.query('SELECT NOW()');
    res.json({ 
      message: 'Enterprise Landing Zone: Operational',
      status: 'Healthy',
      timestamp: dbCheck.rows[0].now 
    });
  } catch (err) {
    console.error('Database Connection Error:', err);
    res.status(500).json({ error: 'Internal Server Error', code: 'DB_FAIL' });
  }
});

// 4. ALB Health Check (Mandatory for Zero-Downtime Deploys)
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.use(AWSXRay.express.closeSegment());

// 5. Graceful Shutdown (The 'Diamond' Touch)
// RUTHLESS NOTE: Amateurs let the app crash. Professionals close connections.
const server = app.listen(port, () => {
  console.log(`Enterprise App listening on port ${port}`);
});

process.on('SIGTERM', () => {
  console.info('SIGTERM signal received. Closing HTTP server and DB pool...');
  server.close(() => {
    pool.end(() => {
      console.log('Server and Pool closed.');
      process.exit(0);
    });
  });
});
