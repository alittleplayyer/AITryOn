
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');

// 允许的文件类型
const ALLOWED_MIME_TYPES = [
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/gif',
  'image/webp'
];

// 验证文件类型和大小
const validateFile = (file) => {
  if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    throw new Error('不支持的文件格式，仅接受PNG、JPG、JPEG、GIF或WebP格式');
  }
  
  if (file.size > 10 * 1024 * 1024) { // 10MB限制
    throw new Error('文件大小超过10MB限制');
  }
  
  return true;
};

// 处理文件并保存为Base64
const processAndSaveFile = async (file, userId) => {
  // 创建用户专属目录
  const userDir = path.join(__dirname, '../uploads', userId.toString());
  const clothesDir = path.join(userDir, 'clothes');
  
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir, { recursive: true });
  }
  
  if (!fs.existsSync(clothesDir)) {
    fs.mkdirSync(clothesDir);
  }
  
  // 生成唯一文件名
  const uniqueFilename = `${uuidv4()}.txt`;
  const filePath = path.join(clothesDir, uniqueFilename);
  
  // 读取文件Buffer并转换为Base64
  const base64Data = file.buffer.toString('base64');
  
  // 保存Base64到文件
  await fs.promises.writeFile(filePath, base64Data);
  
  // 同时保留原始图片（可选，按需求）
  const imageFilename = `${uuidv4()}-original${path.extname(file.originalname)}`;
  const imagePath = path.join(clothesDir, imageFilename);
  await sharp(file.buffer).toFile(imagePath);
  
  return {
    base64FilePath: `/uploads/${userId}/clothes/${uniqueFilename}`,
    originalFilePath: `/uploads/${userId}/clothes/${imageFilename}`
  };
};

module.exports = {
  validateFile,
  processAndSaveFile
};