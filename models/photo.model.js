const mongoose = require('mongoose');

const PhotoSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['personal', 'tryon']  // 照片类型：个人照片或试穿照片
  },
  originalPath: {
    type: String,
    required: true
  },
  compressedPath: {
    type: String,
    required: false // 改为可选
  },
  description:{
    type: String,
    required: false // 描述是可选的
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Photo = mongoose.model('Photo', PhotoSchema);
module.exports = Photo;