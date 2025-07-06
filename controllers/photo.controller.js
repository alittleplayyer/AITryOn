const Photo = require('../models/photo.model');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
console.log(typeof Photo); // 应该输出 'function'
console.log(Photo.create); // 应该输出 [Function: create]
// 压缩并保存照片
const compressImage = async (sourcePath, destPath) => {
  try {
    await sharp(sourcePath)
      .resize(1200, null, { withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toFile(destPath);
    return true;
  } catch (error) {
    console.error('图片压缩错误:', error);
    return false;
  }
};

// 上传照片控制器
exports.uploadPhoto = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { category = 'personal', description = '' } = req.body;
    
    // 1. 检查是否有文件上传
    if (!req.file) {
      return res.status(400).json({ error: '未上传任何文件' });
    }
    
    // 2. 验证分类
    if (!['personal', 'tryon'].includes(category)) {
      return res.status(400).json({ error: '无效的照片分类' });
    }
    
    // 3. 获取原始路径
    const originalPath = req.file.path;
    console.log('原始文件保存位置:', originalPath);
    
    // 4. 创建压缩路径变量（先创建后使用）
    const compressedPath = path.join(
      req.uploadDirs.compressedDir, 
      req.photoFilename
    );
    console.log('压缩文件目标位置:', compressedPath);
    
    // 5. 压缩图片
    const compressionSuccess = await compressImage(originalPath, compressedPath);
    
    // 6. 检查压缩结果
    if (!compressionSuccess) {
      fs.unlinkSync(originalPath);
      return res.status(500).json({ error: '图片处理失败' });
    }
    
    // 7. 创建照片记录
    const photo = await Photo.create({
      user: userId,
      category,
      originalPath,
      compressedPath,
      description
    });
    
    // 8. 返回成功响应
    res.status(201).json({
      success: true,
      message: '照片上传成功',
      data: {
        id: photo._id,
        category: photo.category,
        compressedUrl: `/uploads/${userId}/${category}/compressed/${req.photoFilename}`,
        uploadedAt: photo.uploadedAt
      }
    });
    
  } catch (error) {
    console.error('照片上传错误详情:', {
      message: error.message,
      stack: error.stack,
      requestBody: req.body,
      file: req.file ? {
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path
      } : null
    });
    
    // 清理上传的文件
    if (req.file?.path) {
      fs.unlink(req.file.path, (err) => err && console.error('原始文件清理失败', err));
    }
    
    res.status(500).json({ 
      success: false, 
      error: '服务器错误，照片上传失败' 
    });
  }
};

// 获取用户照片控制器
exports.getUserPhotos = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { category } = req.query;
    
    // 构建查询条件
    const query = { user: userId };
    if (category && ['personal', 'tryon'].includes(category)) {
      query.category = category;
    }
    
    const photos = await Photo.find(query)
      .sort({ uploadedAt: -1 })
      .select('category compressedPath description uploadedAt');
    
    // 添加可直接访问的URL
    const processedPhotos = photos.map(photo => ({
      ...photo._doc,
      url: `/uploads/${userId}/${photo.category}/compressed/${path.basename(photo.compressedPath)}`
    }));
    
    res.json({
      success: true,
      data: processedPhotos
    });
  } catch (error) {
    console.error('获取照片错误:', error);
    res.status(500).json({ success: false, error: '获取照片失败' });
  }
};

// 在照片控制器中添加删除照片功能
exports.deletePhoto = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    
    const photo = await Photo.findById(id);
    if (!photo) {
      return res.status(404).json({ error: '照片未找到' });
    }
    
    // 验证用户拥有此照片
    if (photo.user.toString() !== userId) {
      return res.status(403).json({ error: '无权操作此照片' });
    }
    
    // 删除物理文件
    fs.unlinkSync(photo.originalPath);
    fs.unlinkSync(photo.compressedPath);
    
    // 删除数据库记录
    await Photo.findByIdAndDelete(id);
    
    res.json({ success: true, message: '照片已删除' });
  } catch (error) {
    console.error('删除照片错误:', error);
    res.status(500).json({ error: '删除照片失败' });
  }
};