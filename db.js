const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  statement_timeout: 30000,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

// Garantir que PostgreSQL retorne timestamps no timezone do Brasil
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'America/Sao_Paulo'").catch(() => {});
});

pool.on('remove', () => {
  // Silencioso - conexao removida do pool
});

module.exports = pool;
