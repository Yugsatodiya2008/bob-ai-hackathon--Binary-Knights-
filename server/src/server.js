require('dotenv').config();
const { connectDB } = require('./config/db');
const app = require('./app');
const { seedInitialData } = require('./services/seedService');

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    console.log('[SentinelIQ] Bootstrapping SentinelIQ server...');
    await connectDB();

    // Auto-seed initial scenarios in dev if needed
    if (process.env.AUTO_SEED !== 'false') {
      await seedInitialData();
    }

    const server = app.listen(PORT, () => {
      console.log(`[SentinelIQ] Core Engine listening on port ${PORT}`);
      console.log(`[SentinelIQ] Healthcheck: http://localhost:${PORT}/health`);
      console.log(`[SentinelIQ] API Base: http://localhost:${PORT}/api/v1`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('[SentinelIQ] SIGTERM received. Closing HTTP server...');
      server.close(() => {
        console.log('[SentinelIQ] HTTP server closed.');
        process.exit(0);
      });
    });

    return server;
  } catch (err) {
    console.error('[SentinelIQ] Fatal server initialization error:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { startServer };
