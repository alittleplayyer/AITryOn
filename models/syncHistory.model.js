// models/syncHistory.model.js
const mongoose = require('mongoose');

const syncHistorySchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  action: {
    type: String,
    enum: ['sync', 'manual_upload', 'clipboard'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'success', 'partial_success', 'failed'],
    default: 'pending'
  },
  stats: {
    processed: Number,
    succeeded: Number,
    failed: Number,
    totalSize: Number
  },
  payloadSummary: {
    categories: [String],
    fileCount: Number
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('SyncHistory', syncHistorySchema);