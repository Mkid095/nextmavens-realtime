const express = require('express');
const { postgraphile } = require('postgraphile');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// ============================================================================
// ENVIRONMENT VARIABLE VALIDATION
// ============================================================================

/**
 * Validate required environment variables at startup
 * Fails fast if required variables are missing
 */
function validateEnv() {
  const required = {
    DATABASE_URL: 'PostgreSQL connection string',
    JWT_SECRET: 'JWT secret key for token verification',
  };

  const missing = [];
  const warnings = [];

  for (const [key, description] of Object.entries(required)) {
    if (!process.env[key]) {
      missing.push(`  - ${key}: ${description}`);
    }
  }

  // Warn about insecure defaults
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      warnings.push('  - JWT_SECRET should be at least 32 characters in production');
    }
  }

  if (missing.length > 0) {
    console.error('[FATAL] Missing required environment variables:\n' + missing.join('\n'));
    console.error('[FATAL] Please set these environment variables and restart the service.');
    process.exit(1);
  }

  if (warnings.length > 0) {
    console.warn('[WARN] Security warnings:\n' + warnings.join('\n'));
  }

  // Log configuration (without sensitive values)
  console.log('[Config] Environment validation passed');
  console.log('[Config] NODE_ENV:', process.env.NODE_ENV || 'development');
}

// Validate on startup
validateEnv();

const app = express();

// Configuration
const PORT = process.env.PORT || 4004;
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

// SECURITY: In production, require secure JWT secret
if (IS_PRODUCTION && JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET must be at least 32 characters in production');
  process.exit(1);
}

// PostgreSQL connection pool - NO FALLBACK, only use DATABASE_URL from env
const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: process.env.DATABASE_POOL_MAX || 20,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

// Handle pool errors
pgPool.on('error', (err) => {
  console.error('[PostgreSQL] Unexpected error on idle client', err);
  process.exit(-1);
});

// Log connection (without exposing credentials)
const dbUrlSafe = process.env.DATABASE_URL?.replace(/:[^:@]+@/, ':****@');
console.log('[PostgreSQL] Connecting to:', dbUrlSafe || 'DATABASE_URL not set');

// CORS middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', async (req, res) => {
  try {
    // Check database connection
    const dbCheck = await pgPool.query('SELECT NOW()');

    res.json({
      status: 'ok',
      service: 'graphql-service',
      database: 'connected',
      timestamp: new Date().toISOString(),
      db_time: dbCheck.rows[0].now
    });
  } catch (error) {
    res.status(503).json({
      status: 'degraded',
      service: 'graphql-service',
      database: 'disconnected',
      error: 'Database connection failed'
    });
  }
});

// Get schema info
app.get('/schema', async (req, res) => {
  try {
    const result = await pgPool.query(`
      SELECT
        table_name,
        column_name,
        data_type,
        is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN ('users', 'tenants')
      ORDER BY table_name, ordinal_position
    `);

    const tables = {};
    result.rows.forEach(row => {
      if (!tables[row.table_name]) {
        tables[row.table_name] = { columns: [] };
      }
      tables[row.table_name].columns.push({
        name: row.column_name,
        type: row.data_type,
        nullable: row.is_nullable === 'YES'
      });
    });

    res.json({ tables });
  } catch (error) {
    console.error('Schema query error:', error);
    res.status(500).json({ error: 'Failed to fetch schema' });
  }
});

// JWT pgSettings function for RLS
const pgSettings = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // No auth - just return empty object to use connection's default role
    return {};
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return {
      // Set local variables for RLS policies
      'user.id': String(decoded.userId),
      'user.tenant_id': decoded.tenantId
    };
  } catch (error) {
    return {};
  }
};

// Initialize Postgraphile
const middleware = postgraphile(pgPool, 'public', {
  // GraphQL route
  graphqlRoute: '/graphql',

  // GraphiQL IDE route - DISABLED IN PRODUCTION
  graphiqlRoute: IS_PRODUCTION ? false : '/graphiql',
  graphiql: !IS_PRODUCTION,

  // Watch for schema changes - DISABLED IN PRODUCTION for performance
  watchPg: !IS_PRODUCTION,

  // CORS
  enableCors: true,

  // Classic IDs
  classicIds: true,

  // Setof functions behavior
  setofFunctionsContainNulls: true,

  // Simple collections - use 'omit' to avoid type conflicts
  simpleCollections: 'omit',

  // Dynamic JSON
  dynamicJson: true,

  // Sort order
  sortExport: true,

  // Extended error details - DISABLED IN PRODUCTION to prevent info leakage
  extendedErrors: IS_PRODUCTION ? [] : ['hint', 'detail', 'errcode'],

  // Show error stack - DISABLED IN PRODUCTION
  showErrorStack: !IS_PRODUCTION,

  // PgSettings function for RLS (manual JWT handling)
  pgSettings: pgSettings,

  // Retry on init fail instead of exiting
  retryOnInitFail: true,

  // Maximum query complexity (prevent DoS)
  maxAllowedComplexity: IS_PRODUCTION ? 1000 : undefined,
  maxAllowedDepth: IS_PRODUCTION ? 10 : undefined,
});

// Apply Postgraphile middleware
app.use(middleware);

// Start server
const server = app.listen(PORT, () => {
  console.log(` GraphQL Service running on port ${PORT}`);
  console.log(` Environment: ${NODE_ENV}`);
  console.log(` GraphQL: http://localhost:${PORT}/graphql`);
  if (!IS_PRODUCTION) {
    console.log(` GraphiQL: http://localhost:${PORT}/graphiql`);
  } else {
    console.log(` GraphiQL: DISABLED in production`);
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[System] SIGTERM received, shutting down...');

  // Stop accepting new connections
  server.close(() => {
    console.log('[System] HTTP server closed');
  });

  // Close database pool
  try {
    await pgPool.end();
    console.log('[System] Database pool closed');
  } catch (error) {
    console.error('[System] Error closing database pool:', error);
  }

  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[System] SIGINT received, shutting down...');

  server.close(() => {
    console.log('[System] HTTP server closed');
  });

  try {
    await pgPool.end();
    console.log('[System] Database pool closed');
  } catch (error) {
    console.error('[System] Error closing database pool:', error);
  }

  process.exit(0);
});

module.exports = { app, pgPool, server };
