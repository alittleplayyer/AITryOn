const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const ImageSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: uuidv4
  },
  user_id: {
    type: String,
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  category: {
    type: String,
    enum: ['clothes', 'char', 'vton_results', 'favorites'],
    default: 'clothes'
  },
  url: { type: String, index: true},
  original_url: String,
  page_url: String,
  page_title: String,
  file_size: Number,
  image_width: Number,
  image_height: Number,
  context_info: mongoose.Schema.Types.Mixed,
  status: {
    type: String,
    default: 'saved'
  },
  cloud_synced: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { 
  timestamps: true,
  strict: true // 保持严格模式，但确保所有字段都在Schema中定义
});

// 添加索引优化用户查询
ImageSchema.index({ user_id: 1, uploadDate: -1 });
ImageSchema.index({ user_id: 1, category: 1 });
ImageSchema.index({ user_id: 1, filename: 1 }, { unique: true });
module.exports = mongoose.model('Image', ImageSchema);