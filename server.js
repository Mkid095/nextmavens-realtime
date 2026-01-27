const express = require('express');
const { postgraphile } = require('postgraphile');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Configuration
const PORT = process.env.PORT || 4004;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret';

// PostgreSQL connection pool
const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://nextmavens:Elishiba@95@nextmavens-db-m4sxnf.1.mvuvh68efk7jnvynmv8r2jm2u:5432/nextmavens',
  max: 20
});

// CORS middleware
app.use(cors());
app.use(express.json());

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

// Postgraphile middleware
const middleware = postgraphile(pgPool, 'public', {
  // GraphQL route
  graphqlRoute: '/graphql',

  // GraphiQL IDE route
  graphiqlRoute: '/graphiql',
  graphiql: true,

  // Watch for schema changes
  watchPg: true,

  // CORS
  enableCors: true,

  // Classic IDs
  classicIds: true,

  // Setof functions behavior
  setofFunctionsContainNulls: true,

  // Simple collections (both singular and plural)
  simpleCollections: 'both',

  // Dynamic JSON
  dynamicJson: true,

  // Sort order
  sortExport: true,

  // Extended error details
  extendedErrors: ['hint', 'detail', 'errcode'],

  // Show error stack (disable in production)
  showErrorStack: true,

  // Allow EXPLAIN (admin only)
  allowExplain: () => true,

  // JWT authentication options
  jwtSecret: JWT_SECRET,
  jwtPgTypeIdentifier: 'jwt_token',

  // PgSettings function for RLS
  pgSettings: async (req) => {
    // Extract Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        role: 'anon'
      };
    }

    const token = authHeader.substring(7);

    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.verify(token, JWT_SECRET);

      return {
        role: decoded.role || 'user',
        'user.id': String(decoded.userId),
        'user.tenant_id': decoded.tenantId
      };
    } catch (error) {
      return {
        role: 'anon'
      };
    }
  }
});

// Apply Postgraphile middleware
app.use(middleware);

// Start server
const server = app.listen(PORT, () => {
  console.log(`GraphQL Service running on port ${PORT}`);
  console.log(`GraphQL: http://localhost:${PORT}/graphql`);
  console.log(`GraphiQL: http://localhost:${PORT}/graphiql`);
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
