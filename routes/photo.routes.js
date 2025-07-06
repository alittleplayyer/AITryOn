const express = require('express');
const router = express.Router();
const photoController = require('../controllers/photo.controller');
const upload = require('../config/multer.config');
const authMiddleware = require('../middlewares/auth.middleware');

// 应用认证中间件
router.use(authMiddleware.authenticate);

// 上传照片
router.post('/upload', 
  upload.single('photo'), // 处理单个文件上传
  photoController.uploadPhoto
);

// 获取用户照片
router.get('/', photoController.getUserPhotos);

// 可选：添加删除照片、更新描述等端点
// router.delete('/:id', ...);
// router.patch('/:id', ...);

module.exports = router;