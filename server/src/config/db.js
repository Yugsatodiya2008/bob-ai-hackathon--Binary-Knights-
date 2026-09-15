const mongoose = require('mongoose');

let mongodInstance = null;

const connectDB = async () => {
  try {
    let mongoUri = process.env.MONGO_URI;

    if (process.env.NODE_ENV === 'test' || !mongoUri || process.env.USE_MEMORY_DB === 'true') {
      try {
        const { MongoMemoryServer } = require('mongodb-memory-server');
        mongodInstance = await MongoMemoryServer.create();
        mongoUri = mongodInstance.getUri();
        console.log(`[SentinelIQ] Initialized in-memory Mongo server at: ${mongoUri}`);
      } catch (memErr) {
        console.warn('[SentinelIQ] MongoMemoryServer unavailable, falling back to local URI:', memErr.message);
        mongoUri = mongoUri || 'mongodb://127.0.0.1:27017/sentineliq';
      }
    }

    await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000
    });
    console.log(`[SentinelIQ] Connected to MongoDB at: ${mongoUri}`);
    return mongoose.connection;
  } catch (err) {
    console.error('[SentinelIQ] MongoDB connection error:', err.message);
    throw err;
  }
};

const disconnectDB = async () => {
  try {
    await mongoose.disconnect();
    if (mongodInstance) {
      await mongodInstance.stop();
    }
  } catch (err) {
    console.error('[SentinelIQ] Error during DB disconnect:', err.message);
  }
};

module.exports = {
  connectDB,
  disconnectDB
};
