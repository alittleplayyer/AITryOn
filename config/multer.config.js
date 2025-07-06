const multer = require('multer');
const path = require('path');
const fs = require('fs');

// 确保上传目录存在
const ensureDirExists = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // 添加调试信息
    console.log('上传目标目录:', {
      userId: req.user?.userId,
      category: req.body?.category
    });

    const { userId } = req.user; // 从JWT中获取用户ID
    const category = req.body.category || 'personal'; // 默认分类
    
    // 创建用户专属目录结构
    const userDir = path.join(__dirname, '../uploads', userId);
    const catDir = path.join(userDir, category);
    const originalDir = path.join(catDir, 'original');
    const compressedDir = path.join(catDir, 'compressed');
    
    // 确保所有必要的目录都存在
    ensureDirExists(userDir);
    ensureDirExists(catDir);
    ensureDirExists(originalDir);
    ensureDirExists(compressedDir);
    
    // 存储原始文件到original目录
    req.uploadDirs = { originalDir, compressedDir };
    cb(null, originalDir);
  },
  filename: (req, file, cb) => {

    // 添加调试信息
    console.log('文件名:', file.originalname);
    // ...原有代码...

    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    const filename = `photo-${uniqueSuffix}${ext}`;
    
    // 存储文件名供后续压缩使用
    req.photoFilename = filename;
    cb(null, filename);
  }
});

// 文件过滤器 - 只允许图片文件
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new Error('仅支持图片文件格式！'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB限制
  }
});

module.exports = upload;