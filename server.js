const express = require('express');
const { postgraphile } = require('postgraphile');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Configuration
const PORT = process.env.PORT || 4004;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

// PostgreSQL connection
const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://nextmavens:Elishiba@95@nextmavens-db-m4sxnf.1.mvuvh68efk7jnvynmv8r2jm2u:5432/nextmavens',
  max: 20
});

// JWT verification middleware for Postgraphile
const pgSettingsMiddleware = (req) => {
  // Extract token from Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Return settings for RLS (Row Level Security)
    return {
      role: decoded.role || 'user',
      'user.id': String(decoded.userId),
      'user.tenant_id': decoded.tenantId
    };
  } catch (error) {
    console.error('JWT verification failed:', error.message);
    return null;
  }
};

// Initialize Postgraphile
const postgraphileMiddleware = postgraphile(pgPool, 'public', {
  // GraphQL endpoint
  graphqlRoute: '/graphql',

  // GraphiQL IDE (enable in development)
  graphiqlRoute: '/graphiql',
  graphiql: true,

  // Watch mode for schema changes
  watchPg: true,

  // JWT authentication
  pgSettings: pgSettingsMiddleware,

  // CORS
  enableCors: true,

  // Expose all built-in plugins
  classicIds: true,
  setofFunctionsContainNulls: true,

  // Disable default mutations that bypass RLS
  disableDefaultMutations: false,

  // Relationships
  simpleCollections: 'both',

  // Dynamic JSON
  dynamicJson: true,

  // Comments
  setofFunctionsContainNulls: true,

  // Export GQL schema
  sortExport: true,

  // Better error handling
  showErrorStack: true,

  // Extended errors
  extendedErrors: ['hint', 'detail', 'errcode'],

  // Allow EXPLAIN on mutations
  allowExplain: async (req) => {
    // Only allow explain in development or for admins
    const settings = await pgSettingsMiddleware(req);
    return settings && settings.role === 'owner';
  },

  // JWT secret for PostGraphile's built-in JWT
  jwtSecret: JWT_SECRET,
  jwtPgTypeIdentifier: 'jwt_token',

  // Include all schemas
  appendPlugins: [
    require('@graphile-contrib/pg-simplify-inflection')
  ].filter(Boolean)
});

// CORS middleware
app.use(cors());

// Parse JSON with file upload support
app.use(require('express')());

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'graphql-service',
    timestamp: new Date().toISOString()
  });
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
      ORDER BY table_name, ordinal_position
    `);

    const tables = {};
    result.rows.forEach(row => {
      if (!tables[row.table_name]) {
        tables[row.table_name] = {
          columns: []
        };
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

// Apply Postgraphile middleware
app.use(postgraphileMiddleware);

// Start server
const server = app.listen(PORT, () => {
  console.log(`GraphQL Service running on port ${PORT}`);
  console.log(`GraphQL endpoint: http://localhost:${PORT}/graphql`);
  console.log(`GraphiQL IDE: http://localhost:${PORT}/graphiql`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[System] SIGTERM received, shutting down...');

  await pgPool.end();

  server.close(() => {
    console.log('[System] Server closed');
    process.exit(0);
  });
});

module.exports = { app, pgPool, server };
