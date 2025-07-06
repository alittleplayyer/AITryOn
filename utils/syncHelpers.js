const Image = require('../models/image.model');
const SyncHistory = require('../models/syncHistory.model');

// 处理图片数据同步
async function processImageSync(userId, imagesMetadata, imageFiles, session) {
  const results = {
    upsertedCount: 0,
    deletedCount: 0,
    failedCount: 0,
    details: []
  };

  // 批量更新或插入图片记录
  const bulkOps = imagesMetadata.map(meta => {
    const imageData = {
      userId,
      filename: meta.filename,
      url: `/uploads/${userId}/${meta.context_info?.category || 'clothes'}/${meta.filename}`,
      category: meta.context_info?.category || 'clothes',
      size: meta.file_size || 0,
      metadata: {
        ...meta.context_info,
        source: 'sync',
        original_timestamp: meta.upload_timestamp
      }
    };

    return {
      updateOne: {
        filter: { userId, filename: meta.filename },
        update: { $set: imageData },
        upsert: true
      }
    };
  });

  // 执行批量操作
  if (bulkOps.length > 0) {
    const bulkResult = await Image.bulkWrite(bulkOps, { session });
    results.upsertedCount = bulkResult.upsertedCount + bulkResult.modifiedCount;
  }

  // 处理缺失文件标记（可选）
  const receivedFilenames = imagesMetadata.map(img => img.filename);
  const deleteResult = await Image.deleteMany(
    { 
      userId, 
      filename: { $nin: receivedFilenames },
      'metadata.source': 'sync' // 只删除之前同步的记录
    },
    { session }
  );
  results.deletedCount = deleteResult.deletedCount;

  return results;
}

// 创建同步记录
async function createSyncRecord(userId, payload, results, session) {
  return await SyncHistory.create([{
    userId,
    action: 'user_sync',
    status: 'completed',
    clientTimestamp: payload.sync_timestamp,
    stats: {
      received: payload.sync_statistics.total_metadata_records,
      processed: results.upsertedCount,
      errors: results.failedCount
    },
    payloadSummary: {
      categories: payload.sync_statistics.categories,
      totalSize: payload.sync_statistics.total_size
    }
  }], { session });
}

module.exports = {
  processImageSync,
  createSyncRecord
};