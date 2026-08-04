const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  statement_timeout: 30000,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

pool.on('error', (err) => {
  console.error('Erro fatal no pool do PostgreSQL:', err.message);
});

pool.on('connect', () => {
  // Silencioso - conexao bem sucedida
});

pool.on('remove', () => {
  // Silencioso - conexao removida do pool
});

module.exports = pool;
