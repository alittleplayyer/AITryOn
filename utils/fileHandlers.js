const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');
const { ALLOWED_MIME_TYPES } = require('./constants');
const Image = require('../models/image.model');


// 确保用户存储空间存在
exports.ensureUserStorage = async (userId) => {
  const userStoragePath = path.join(__dirname, '../uploads', userId.toString());
  
  if (!fs.existsSync(userStoragePath)) {
    fs.mkdirSync(userStoragePath, { recursive: true });
    
    // 创建默认分类目录
    const defaultCategories = ['clothes', 'char', 'unsorted'];
    defaultCategories.forEach(category => {
      const categoryPath = path.join(userStoragePath, category);
      if (!fs.existsSync(categoryPath)) {
        fs.mkdirSync(categoryPath);
      }
    });
  }
  
  return userStoragePath;
};

// 删除过期的数据URL前缀（如 "data:image/png;base64,"）
const extractBase64 = (dataURL) => {
  const base64Data = dataURL.replace(/^data:image\/\w+;base64,/, '');
  return Buffer.from(base64Data, 'base64');
};

// 验证Base64图片数据
const validateImageData = (buffer, maxSize = 10 * 1024 * 1024) => {
  if (buffer.length > maxSize) {
    throw new Error(`文件大小超过${maxSize / (1024 * 1024)}MB限制`);
  }
  
  // 使用sharp快速验证图片格式
  return sharp(buffer)
    .metadata()
    .then(metadata => {
      if (!metadata || !ALLOWED_MIME_TYPES.includes(`image/${metadata.format}`)) {
        throw new Error('不支持的文件格式，仅接受PNG、JPG、JPEG、GIF或WebP格式');
      }
      return metadata;
    });
};

// 保存图片文件
const saveImageFile = async (buffer, userId, category, filename) => {
  const userDir = path.join(__dirname, '../uploads', userId);
  if (userId === 'anonymous'){
    userDir = userId === 'anonymous' ? 
    path.join(baseDir, 'anonymous', category || 'unsorted') :
    path.join(baseDir, userId, category || 'clothes');
  }
  const categoryDir = path.join(userDir, category);

  // 确保目录存在
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir, { recursive: true });
  }
  
  if (!fs.existsSync(categoryDir)) {
    fs.mkdirSync(categoryDir);
  }
  
  // 保存后记录到数据库
  const imageDoc = await Image.create({
    userId,
    filename,
    url: `/uploads/${userId}/${category}/${filename}`,
    category: category || 'unsorted',
    size: buffer.length,
    metadata: {
      ...metadata,
      source: metadata.source || 'upload'
    }
  });

  const filePath = path.join(categoryDir, filename);
  await fs.promises.writeFile(filePath, buffer);
  
  // === 缩略图预生成 ===
  try {
    const thumbnailPath = path.join(
      path.dirname(filePath), 
      'thumbnails', 
      filename.replace(/(\.\w+)$/, '_thumb$1')
    );
    
    await sharp(buffer)
      .resize(200, 200, { fit: 'inside' })
      .toFile(thumbnailPath);
      
    console.log(`缩略图已生成: ${thumbnailPath}`);
  } catch (err) {
    console.error('缩略图生成失败:', err);
  }

  return {
    url: `/uploads/${userId}/${category}/${filename}`,
    absolutePath: filePath,
    imageId: imageDoc._id
  };
};

// 生成缩略图
const generateThumbnail = async (inputPath) => {
  const outputPath = inputPath
    .replace('/uploads/', '/thumbnails/')
    .replace(/(\.\w+)$/, '_thumb$1');

  await sharp(inputPath)
    .resize(200, 200, { fit: 'inside' })
    .toFile(outputPath);

  return outputPath.replace(path.join(__dirname, '../'), '');
};

module.exports = {
  extractBase64,
  validateImageData,
  saveImageFile,
  generateThumbnail
};