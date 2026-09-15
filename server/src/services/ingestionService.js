const crypto = require('crypto');
const RawEvent = require('../models/RawEvent');
const QuarantineEvent = require('../models/QuarantineEvent');

const SUPPORTED_SOURCES = ['crowdstrike', 'splunkevent', 'suricata', 'generic_webhook'];

const computePayloadHash = (payload) => {
  const content = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return crypto.createHash('sha256').update(content).digest('hex');
};

const ingestPayload = async ({ sourceType, rawPayload, headers = {} }) => {
  // 1. Validate source type
  if (!SUPPORTED_SOURCES.includes(sourceType)) {
    const quarantined = await QuarantineEvent.create({
      sourceType: sourceType || 'unknown',
      rawPayload,
      reason: `Unsupported source type: ${sourceType}`,
      validationErrors: [{ path: 'sourceType', message: `Must be one of ${SUPPORTED_SOURCES.join(', ')}` }]
    });
    return { status: 'QUARANTINED', quarantineId: quarantined._id, error: 'Unsupported source type' };
  }

  // 2. Validate payload structure (not empty, valid object or parsable JSON)
  if (!rawPayload || (typeof rawPayload === 'object' && Object.keys(rawPayload).length === 0)) {
    const quarantined = await QuarantineEvent.create({
      sourceType,
      rawPayload: rawPayload ?? null,
      reason: 'Empty or malformed payload',
      validationErrors: [{ path: 'payload', message: 'Payload cannot be null or empty' }]
    });
    return { status: 'QUARANTINED', quarantineId: quarantined._id, error: 'Empty or malformed payload' };
  }

  try {
    let parsedPayload = rawPayload;
    if (typeof rawPayload === 'string') {
      try {
        parsedPayload = JSON.parse(rawPayload);
      } catch (parseError) {
        const quarantined = await QuarantineEvent.create({
          sourceType,
          rawPayload,
          reason: `JSON parse error: ${parseError.message}`,
          validationErrors: [{ path: 'payload', message: parseError.message }]
        });
        return { status: 'QUARANTINED', quarantineId: quarantined._id, error: 'Unparseable JSON' };
      }
    }

    const payloadHash = computePayloadHash(parsedPayload);

    // Save to raw_events
    const rawEvent = await RawEvent.create({
      sourceType,
      payload: parsedPayload,
      headers: headers,
      payloadHash,
      status: 'RECEIVED'
    });

    return {
      status: 'SUCCESS',
      rawEventId: rawEvent._id,
      payloadHash,
      sourceType
    };
  } catch (err) {
    // Under no circumstance drop the event - quarantine on any unexpected error
    const quarantined = await QuarantineEvent.create({
      sourceType,
      rawPayload,
      reason: `Ingestion failure: ${err.message}`,
      validationErrors: [{ path: 'exception', message: err.message }]
    });
    return { status: 'QUARANTINED', quarantineId: quarantined._id, error: err.message };
  }
};

module.exports = {
  ingestPayload,
  computePayloadHash,
  SUPPORTED_SOURCES
};
