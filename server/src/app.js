const express = require('express');
const cors = require('cors');
const { authMiddleware } = require('./middleware/auth');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Healthcheck
app.get('/health', (req, res) => {
  res.json({ status: 'HEALTHY', system: 'SentinelIQ', timestamp: new Date().toISOString() });
});

// Authentication & TLP Context Middleware on all API v1 endpoints
app.use('/api/v1', authMiddleware);

// Mount routes
const ingestRoutes = require('./routes/ingest');
const normalizeRoutes = require('./routes/normalize');
const incidentRoutes = require('./routes/incidents');
const pipelineRoutes = require('./routes/pipeline');
const blufRoutes = require('./routes/bluf');
const quarantineRoutes = require('./routes/quarantine');
const auditRoutes = require('./routes/audit');

app.use('/api/v1', ingestRoutes);
app.use('/api/v1', normalizeRoutes);
app.use('/api/v1', incidentRoutes);
app.use('/api/v1', pipelineRoutes);
app.use('/api/v1', blufRoutes);
app.use('/api/v1', quarantineRoutes);
app.use('/api/v1', auditRoutes);

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[SentinelIQ Global Error]:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

module.exports = app;
