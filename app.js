require('dotenv').config(); // 这必须是第一行代码！
const { extractBase64, validateImageData, saveImageFile } = require('./utils/fileHandlers');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const router = express.Router();
const User = require('./models/user.model'); 
const app = express();
const TokenBlacklist = require('./models/tokenBlacklist.model'); 
const Image = require('./models/image.model');
const os = require('os');
const redis = require('./utils/redis');
const fs = require('fs');
const { MongoClient } = require('mongodb');
const SyncHistory = require('./models/syncHistory.model');

// 使用环境变量或配置
const JWT_SECRET = process.env.JWT_SECRET || 'fallbackSecret';

const fsp = fs.promises || {
  writeFile: (path, data) => new Promise((resolve, reject) => {
    fs.writeFile(path, data, (err) => {
      if (err) reject(err);
      else resolve();
    });
  }),
  readdir: (path) => new Promise((resolve, reject) => {
    fs.readdir(path, (err, files) => {
      if (err) reject(err);
      else resolve(files);
    });
  }),
  access: (path) => new Promise((resolve, reject) => {
    fs.access(path, (err) => {
      if (err) reject(err);
      else resolve();
    });
  })
};

// 使用body-parser中间件 - 增加大小限制
app.use(bodyParser.json({ limit: '50mb' })); // 增加到50MB
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true })); // 也增加urlencoded的限制

// 支持的图片分类
const ALLOWED_CATEGORIES = ['clothes', 'char', 'vton_results', 'favorites'];

// 处理同步请求
router.post('/sync/user/:user_id', async (req, res) => {

  const startTime = Date.now();
  const { user_id } = req.params;


  try {
    const syncData = req.body;
    console.log('接收到的同步数据:', typeof syncData, syncData ? Object.keys(syncData) : '空');
    // 验证请求体存在且是对象
    if (!syncData || typeof syncData !== 'object' || Array.isArray(syncData)) {
      return res.status(400).json({
        success: false,
        error: '请求体必须是有效的JSON对象'
      });
    }

    // 解析数据
    const {
      user_info = {},
      images_metadata = [],
      image_files = {},
      sync_timestamp,
      sync_statistics = {}
    } = syncData;

    // 验证基本数据结构
    if (!Array.isArray(images_metadata)) {
      return res.status(400).json({
        success: false,
        error: 'images_metadata 必须是数组'
      });
    }

    if (typeof image_files !== 'object' || image_files === null) {
      return res.status(400).json({
        success: false,
        error: 'image_files 必须是对象'
      });
    }

    // 准备同步结果
    const syncResults = {
      upsertedCount: 0,
      failedCount: 0,
      details: [],
      categories: new Set(),
      fileSizes: []
    };

    // 创建用户目录
    const userDir = path.join(__dirname, '././uploads', user_id);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
      console.log(`用户目录创建成功: ${userDir}`);
    }
    console.log(`[同步开始] 用户ID: ${user_id}，接收元数据数量: ${images_metadata.length}，文件数量: ${Object.keys(image_files).length}`);
    // 处理每张图片
    for (const metadata of images_metadata) {
      const fileDetails = {
        filename: metadata.filename,
        status: 'pending',
        error: null,
        imageId: null
      };

      try {
        // 验证必要字段
        if (!metadata.filename) {
          throw new Error('缺少文件名');
        }

        console.log(`处理元数据: ${metadata.filename}`);
        console.log(`文件数据键: ${Object.keys(image_files)}`);
        // 获取文件数据
        const dataURL = image_files[metadata.filename];
        if (!dataURL) {
          throw new Error('找不到对应的图片数据');
        }

        // 提取base64数据
        const base64Data = dataURL.replace(/^data:image\/\w+;base64,/, '');
        const imageBuffer = Buffer.from(base64Data, 'base64');

        // 验证分类
        let category = metadata.category || 'clothes';
        if (!ALLOWED_CATEGORIES.includes(category)) {
          category = 'clothes'; // 默认分类
        }

        // 创建分类目录
        const categoryDir = path.join(userDir, category);
        if (!fs.existsSync(categoryDir)) {
          fs.mkdirSync(categoryDir, { recursive: true });
          console.log(`分类目录创建成功: ${categoryDir}`);
        }

        console.log(`用户目录: ${userDir}, 存在: ${fs.existsSync(userDir)}`);
        console.log(`分类目录: ${categoryDir}, 存在: ${fs.existsSync(categoryDir)}`);

        // 保存图片文件
        const filePath = path.join(categoryDir, metadata.filename);
        //await fs.promises.writeFile(filePath, imageBuffer);
        fs.writeFileSync(filePath, imageBuffer);
        console.log(`图片保存成功: ${filePath}`);

        // 构建URL
        const imageUrl = `/uploads/${user_id}/${category}/${metadata.filename}`;

        // 准备数据库记录
        const imageData = {
          user_id,
          filename: metadata.filename,
          category,
          url: imageUrl, // 确保URL有值
          file_size: imageBuffer.length,
          cloud_synced: true,
          original_url: metadata.original_url || null,
          page_url: metadata.page_url || null,
          page_title: metadata.page_title || null,
          image_width: metadata.image_width || null,
          image_height: metadata.image_height || null,
          context_info: metadata.context_info || {},
          status: metadata.status || 'saved'
        };

        // 更新或创建图片记录
        // 使用findOneAndUpdate避免唯一索引冲突
        const result = await Image.findOneAndUpdate(
          { user_id, filename: metadata.filename },
          imageData,
          {
            upsert: true,
            new: true,
            runValidators: true,
            setDefaultsOnInsert: true
          }
        );

        syncResults.upsertedCount++;
        syncResults.categories.add(category);
        syncResults.fileSizes.push(imageBuffer.length);

        fileDetails.status = 'upserted';
        fileDetails.imageId = result._id;
        fileDetails.url = imageUrl;
        fileDetails.category = category;

      } catch (err) {
        console.error(`处理图片 ${metadata.filename || 'unknown'} 失败:`, err);
        syncResults.failedCount++;
        fileDetails.status = 'failed';
        fileDetails.error = err.message;
      }

      syncResults.details.push(fileDetails);
    }

    // 计算总文件大小
    const totalFileSize = syncResults.fileSizes.reduce((sum, size) => sum + size, 0);

    // 返回响应
    const response = {
      success: true,
      sync_id: Date.now(),
      user_id,
      stats: {
        total_received: images_metadata.length,
        upserted: syncResults.upsertedCount,
        failed: syncResults.failedCount,
        total_size: totalFileSize,
        categories: Array.from(syncResults.categories)
      },
      timestamps: {
        client_sync: sync_timestamp,
        server_received: new Date().toISOString(),
        processing_time: `${Date.now() - startTime}ms`
      },
      details: syncResults.details
    };

    res.status(200).json(response);

  } catch (error) {
    console.error('同步处理失败:', error);
    res.status(500).json({
      success: false,
      error: '同步处理失败',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


module.exports = router;

// JWT认证中间件
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: '无效或过期的令牌' });
    }

    req.user = {
      userId: decoded.userId,
      role: decoded.role
    };
    next();
  });
};


// 连接MongoDB - 仅保留一个连接方式
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// 统一使用router定义路由


//获取服务器状态
router.get('/status', async (req, res) => {
  try {
    // 1. 基础服务器状态
    const serverStatus = {
      status: 'operational',
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    };

    // 2. 数据库检查（简化版）
    try {
      await mongoose.connection.db.admin().ping();
      serverStatus.database = 'connected';
    } catch (err) {
      serverStatus.database = 'disconnected';
      serverStatus.status = 'degraded';
    }

    // 3. 返回简化状态
    res.json(serverStatus);

  } catch (error) {
    console.error('状态检查失败:', error);
    // 返回简化错误信息
    res.status(500).json({
      status: 'down',
      error: 'Internal Server Error'
    });
  }
});

router.get('/user/:user_id/sync/status', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { limit = 10, since } = req.query;

    // 添加调试日志
    console.log(`[权限检查] URL用户ID: ${userId}, 类型: ${typeof userId}`);
    console.log(`[权限检查] 令牌用户ID: ${req.user.userId}, 类型: ${typeof req.user.userId}`);


    // 1. 验证用户权限
    if (String(userId) !== String(req.user.userId)) {
      console.log(`[权限错误] 用户ID不匹配: URL=${userId} vs Token=${req.user.userId}`);
      return res.status(403).json({
        success: false,
        error: '无权查看其他用户的同步状态'
      });
    }

    // 2. 构建查询条件
    const query = { userId: userId };
    if (since) {
      query.createdAt = { $gte: new Date(since) };
    }

    // 3. 获取同步历史记录
    const syncHistory = await SyncHistory.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();

    // 4. 获取汇总统计
    const stats = await SyncHistory.aggregate([
      { $match: { userId: userId } },
      {
        $group: {
          _id: null,
          totalSyncs: { $sum: 1 },
          lastSuccess: { $max: "$createdAt" },
          avgProcessed: { $avg: "$stats.processed" },
          categories: { $addToSet: "$payloadSummary.categories" }
        }
      },
      {
        $project: {
          _id: 0,
          totalSyncs: 1,
          lastSuccess: 1,
          avgProcessed: 1,
          uniqueCategories: {
            $reduce: {
              input: "$categories",
              initialValue: [],
              in: { $setUnion: ["$$value", "$$this"] }
            }
          }
        }
      }
    ]);

    // 5. 构造响应数据
    const response = {
      success: true,
      userId,
      sync_status: syncHistory.length > 0 ? 'active' : 'inactive',
      stats: stats[0] || {
        totalSyncs: 0,
        lastSuccess: null,
        avgProcessed: 0,
        uniqueCategories: []
      },
      sync_history: syncHistory.map(record => ({
        id: record._id,
        action: record.action,
        status: record.status,
        timestamp: record.createdAt,
        stats: record.stats,
        payload_summary: record.payloadSummary
      })),
      links: {
        initiate_sync: `/api/sync/user/${userId}`,
        detailed_history: `/api/user/${userId}/sync/history`
      }
    };

    res.status(200).json(response);

  } catch (error) {
    console.error('同步状态查询失败:', error);
    res.status(500).json({
      success: false,
      error: '查询同步状态失败',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

router.get('/status', async (req, res) => {
  try {
    // 1. 基础服务器状态
    const serverStatus = {
      timestamp: new Date().toISOString(),
      status: 'operational',
      uptime: process.uptime(),
      server: {
        hostname: os.hostname(),
        platform: os.platform(),
        memory: {
          free: `${(os.freemem() / 1024 / 1024).toFixed(2)} MB`,
          total: `${(os.totalmem() / 1024 / 1024).toFixed(2)} MB`,
          usage: `${((1 - os.freemem() / os.totalmem()) * 100).toFixed(1)}%`
        },
        cpu: {
          cores: os.cpus().length,
          load: os.loadavg().map(load => load.toFixed(2))
        }
      }
    };

    // 2. 数据库连接检查
    let dbStatus = 'unchecked';
    try {
      const client = await MongoClient.connect(process.env.MONGODB_URI, {
        connectTimeoutMS: 5000,
        serverSelectionTimeoutMS: 5000
      });
      await client.db().admin().ping();
      dbStatus = 'connected';
      await client.close();
    } catch (err) {
      dbStatus = `error: ${err.message}`;
      serverStatus.status = 'degraded';
    }

    // 3. 文件系统检查
    let storageStatus;
    try {
      const stats = fs.statSync(path.join(__dirname, '../uploads'));
      storageStatus = {
        writable: true,
        freeSpace: `${(stats.freeSpace / 1024 / 1024).toFixed(2)} MB`
      };
    } catch (err) {
      storageStatus = {
        writable: false,
        error: err.message
      };
      serverStatus.status = 'degraded';
    }

    // 4. 外部服务检查（示例：Redis）
    let redisStatus = 'disabled';
    if (process.env.REDIS_URL) {
      try {
        const redis = require('../utils/redis');
        await redis.ping();
        redisStatus = 'connected';
      } catch (err) {
        redisStatus = `error: ${err.message}`;
        serverStatus.status = 'degraded';
      }
    }

    // 5. 整合响应数据
    const response = {
      ...serverStatus,
      dependencies: {
        database: dbStatus,
        storage: storageStatus,
        redis: redisStatus,
        // 添加其他服务检查...
      },
      metrics: {
        imageCount: await Image.countDocuments(),
        activeUsers: await User.countDocuments({ lastLogin: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } })
      }
    };

    res.json(response);

  } catch (error) {
    console.error('状态检查失败:', error);
    res.status(500).json({
      status: 'down',
      error: '深度检查失败',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


router.get('/auth/check', authenticateJWT, async (req, res) => {
  try {
    // 从JWT认证中间件中获取用户信息
    const user = await User.findById(req.user.userId).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: '用户不存在'
      });
    }

    res.json({
      success: true,
      isAuthenticated: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      tokenValid: true,
      expiresIn: '1h' // 与JWT配置保持一致
    });
  } catch (err) {
    console.error('登录状态检查错误:', err);
    res.status(500).json({
      success: false,
      error: '服务器错误'
    });
  }
});



router.post('/register', async (req, res) => {
  const { local_user_id, username, email, password } = req.body;
  try {
    // 1. 创建用户记录
    const user = await User.create({
      _id: local_user_id,
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
    });

    // 先保存用户
    //await user.save();
    const userId = user._id.toString();
    // 2. 为用户创建存储空间
    const uploadsDir = path.join(process.cwd(), 'uploads'); // 使用process.cwd()确保正确根目录
    const userStoragePath = path.join(uploadsDir, userId);

    console.log('尝试创建目录:', userStoragePath); // 调试日志

    try {
      // 确保上传目录存在
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
        console.log('已创建uploads目录');
      }

      // 创建用户目录
      if (!fs.existsSync(userStoragePath)) {
        fs.mkdirSync(userStoragePath, { recursive: true });
        console.log('已创建用户目录:', userStoragePath);

        // 创建默认分类目录
        const defaultCategories = ['clothes', 'char', 'vton_result', 'favorites'];
        for (const category of defaultCategories) {
          const categoryPath = path.join(userStoragePath, category);
          if (!fs.existsSync(categoryPath)) {
            fs.mkdirSync(categoryPath);
            console.log('已创建分类目录:', categoryPath);
          }
        }
      }
    } catch (fsErr) {
      console.error('创建存储目录失败:', fsErr);
      // 回滚用户创建
      await User.deleteOne({ _id: userId });
      return res.status(500).json({
        success: false,
        error: '无法创建用户存储空间',
        details: fsErr.message
      });
    }

    // 3. 返回成功响应
    res.status(200).json({
      success: true,
      cloud_user_id: userId,  // 测试期望的字段
      username: user.username,
      email: user.email,
      //role: user.role,
      storagePath: userStoragePath // 可选：返回存储路径给前端
    });

  } catch (err) {
    // 错误处理（保持不变）
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(409).json({
        success: false,
        error: `${field === 'email' ? '邮箱' : '用户名'}已被使用`
      });
    }

    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(val => val.message);
      return res.status(400).json({
        success: false,
        error: errors.join(', ')
      });
    }

    console.error('注册错误:', err);
    res.status(500).json({
      success: false,
      error: '服务器错误',
      details: err.message
    });
  }
});

// 配置参数
const UPLOAD_ROOT = path.join(__dirname, './uploads'); // 上传根目录
const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const BASE_URL = 'http://localhost:6006';

//使用username和password登录
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. 用户认证
    const user = await User.findOne({ username }).select('+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: '无效凭证' });
    }

    // 2. 生成JWT令牌
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'fallbackSecret',
      { expiresIn: '1h' }
    );

    // 3. 准备按分类的图片数据
    const imagesByCategory = {};
    const userId = user._id.toString();
    const userDir = path.join(UPLOAD_ROOT, userId);

    // 4. 检查用户目录是否存在
    if (fs.existsSync(userDir)) {
      // 遍历所有分类
      for (const category of ALLOWED_CATEGORIES) {
        const categoryDir = path.join(userDir, category);

        // 检查分类目录是否存在
        if (fs.existsSync(categoryDir)) {
          try {
            // 读取目录内容（使用同步方法）
            const files = fs.readdirSync(categoryDir);

            // 过滤并映射图片数据
            imagesByCategory[category] = files
              .filter(file => IMAGE_EXTENSIONS.includes(path.extname(file).toLowerCase()))
              .map(file => ({
                filename: file,
                url: `${BASE_URL}/uploads/${userId}/${category}/${file}`,
                category: category
              }));
          } catch (readError) {
            console.error(`读取分类目录失败: ${categoryDir}`, readError);
            imagesByCategory[category] = [];
          }
        } else {
          imagesByCategory[category] = [];
        }
      }
    } else {
      // 用户目录不存在，所有分类都为空
      ALLOWED_CATEGORIES.forEach(category => {
        imagesByCategory[category] = [];
      });
    }

    // 5. 构建响应数据
    res.json({
      success: true,
      token,
      user: {
        id: userId,
        username: user.username,
        email: user.email,
        role: user.role
      },
      images: imagesByCategory
    });

  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ success: false, error: '服务器错误' });
  }
});

// logout路由，使用黑名单机制
router.post('/logout', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, error: '未提供令牌' });
    }

    // 验证令牌是否有效（但不中断流程）
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      const expiresAt = err ? new Date(Date.now() + 3600 * 1000) : new Date(decoded.exp * 1000);

      // 将令牌加入黑名单
      await TokenBlacklist.create({
        token,
        expiresAt
      });

      res.json({
        success: true,
        message: '登出成功'
      });
    });
  } catch (err) {
    console.error('登出错误:', err);
    res.status(500).json({ success: false, error: '服务器错误' });
  }
});

// 接收浏览器插件发送的图片（支持未登录用户）
router.post('/receive-image', async (req, res) => {
  try {
    // 验证请求体结构（简化版，不需要用户信息）
    const { images_metadata, image_files } = req.body;

    if (!images_metadata || !Array.isArray(images_metadata) || images_metadata.length === 0) {
      return res.status(400).json({
        success: false,
        error: '缺少图片元数据或格式不正确'
      });
    }

    if (!image_files || typeof image_files !== 'object' || Object.keys(image_files).length === 0) {
      return res.status(400).json({
        success: false,
        error: '缺少图片文件数据'
      });
    }

    const results = [];
    const errors = [];
    const defaultUserId = 'anonymous'; // 为未登录用户设置默认用户ID

    // 处理所有图片
    for (const metadata of images_metadata) {
      const filename = metadata.filename;
      const dataURL = image_files[filename];

      if (!dataURL) {
        errors.push({
          filename,
          error: `找不到对应的图片数据: ${filename}`,
          metadata
        });
        continue;
      }

      try {
        // 提取并验证图片
        const imageBuffer = extractBase64(dataURL);
        await validateImageData(imageBuffer);

        // 保存文件到匿名用户目录
        const { url } = await saveImageFile(
          imageBuffer,
          defaultUserId,
          metadata.context_info?.category || 'unsorted', // 默认分类
          filename
        );

        results.push({
          ...metadata,
          saved_url: url,
          saved_at: new Date().toISOString(),
          status: 'saved',
          user_id: defaultUserId // 标明这是匿名用户上传
        });
      } catch (err) {
        errors.push({
          filename,
          error: err.message,
          metadata
        });
      }
    }

    // 准备响应数据（简化版）
    const response = {
      success: errors.length === 0,
      sync_timestamp: new Date().toISOString(),
      stats: {
        received: images_metadata.length,
        saved: results.length,
        failed: errors.length
      }
    };

    if (results.length > 0) response.results = results;
    if (errors.length > 0) response.errors = errors;

    const statusCode = errors.length === 0 ? 200 : errors.length === images_metadata.length ? 400 : 207;
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('浏览器插件上传处理错误:', error);
    res.status(500).json({
      success: false,
      error: '服务器处理请求失败'
    });
  }
});

// 接收剪切板上传的图片（支持未登录用户）
router.post('/upload-clipboard', async (req, res) => {
  try {
    const { imageData, category = 'clothes', pageInfo = {} } = req.body;

    // 1. 基础验证
    if (!imageData) {
      return res.status(400).json({
        success: false,
        error: '剪切板中没有图片数据'
      });
    }

    // 2. 处理匿名用户
    const userId = req.user?.userId || 'anonymous';
    const validCategories = ['clothes', 'char', 'unsorted'];
    const sanitizedCategory = validCategories.includes(category) ? category : 'unsorted';

    // 3. 生成文件名和路径
    const timestamp = Date.now();
    const fileExt = imageData.split(';')[0].split('/')[1] || 'png';
    const filename = `clip_${timestamp}.${fileExt}`;

    // 4. 提取并验证图片数据
    let imageBuffer;
    try {
      const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
      imageBuffer = Buffer.from(base64Data, 'base64');

      // 简单验证（可选）
      if (imageBuffer.length > 10 * 1024 * 1024) { // 10MB限制
        throw new Error('图片大小超过10MB限制');
      }
    } catch (err) {
      return res.status(400).json({
        success: false,
        error: '无效的图片数据格式'
      });
    }

    // 5. 保存文件（使用您现有的saveImageFile工具函数）
    const { url } = await saveImageFile(
      imageBuffer,
      userId,
      sanitizedCategory,
      filename
    );

    // 6. 构造响应数据
    const response = {
      success: true,
      imageInfo: {
        id: `clip_${timestamp}`,
        url,
        category: sanitizedCategory,
        size: imageBuffer.length,
        source: 'clipboard',
        pageInfo, // 保留原始页面信息
        isAnonymous: true // 标记是否为匿名上传
      },
      message: '剪切板图片已保存'
    };

    res.status(201).json(response);

  } catch (error) {
    console.error('剪切板图片上传错误:', error);
    res.status(500).json({
      success: false,
      error: error.message || '服务器处理失败'
    });
  }
});

// 文件上传路由
router.post('/upload-file', authenticateJWT, async (req, res) => {
  try {
    // 验证请求体结构
    const { user_info, images_metadata, image_files } = req.body;

    if (!user_info || !user_info.user_id) {
      return res.status(400).json({
        success: false,
        error: '缺少用户信息或用户ID'
      });
    }

    if (!images_metadata || !Array.isArray(images_metadata) || images_metadata.length === 0) {
      return res.status(400).json({
        success: false,
        error: '缺少图片元数据或格式不正确'
      });
    }

    if (!image_files || typeof image_files !== 'object' || Object.keys(image_files).length === 0) {
      return res.status(400).json({
        success: false,
        error: '缺少图片文件数据'
      });
    }

    // 验证用户身份（请求中的用户ID与JWT令牌中的用户ID一致）
    if (user_info.user_id !== req.user.userId) {
      return res.status(403).json({
        success: false,
        error: '无权访问此用户资源'
      });
    }

    const results = [];
    const errors = [];

    // 处理所有图片
    for (const metadata of images_metadata) {
      const filename = metadata.filename;
      const dataURL = image_files[filename];

      if (!dataURL) {
        errors.push({
          filename,
          error: `找不到对应的图片数据: ${filename}`,
          metadata
        });
        continue;
      }

      try {
        // 提取并验证图片
        const imageBuffer = extractBase64(dataURL);
        await validateImageData(imageBuffer);

        // 保存文件
        const { url } = await saveImageFile(
          imageBuffer,
          user_info.user_id,
          metadata.context_info?.category || 'clothes',
          filename
        );

        results.push({
          ...metadata,
          saved_url: url,
          saved_at: new Date().toISOString(),
          status: 'saved'
        });
      } catch (err) {
        errors.push({
          filename,
          error: err.message,
          metadata
        });
      }
    }

    // 准备响应数据
    const response = {
      success: errors.length === 0,
      sync_timestamp: new Date().toISOString(),
      sync_statistics: {
        total_metadata_records: images_metadata.length,
        total_files_found: results.length,
        total_files_missing: errors.length,
        total_size: results.reduce((sum, item) => sum + (item.file_size || 0), 0),
        categories: [...new Set(results.map(item => item.context_info?.category || 'clothes'))]
      }
    };

    // 包含成功和失败结果
    if (results.length > 0) {
      response.results = results;
    }
    if (errors.length > 0) {
      response.errors = errors;
      response.error_message = `处理完成，但有${errors.length}个错误`;
    }

    // 返回状态取决于是否有错误
    const statusCode = errors.length === 0 ? 200 : errors.length === images_metadata.length ? 400 : 207;
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('文件上传处理错误:', error);
    res.status(500).json({
      success: false,
      error: error.message || '服务器处理请求失败'
    });
  }
});

router.get('/user/images', authenticateJWT, async (req, res) => {
  try {
    // 1. 检查缓存
    const cacheKey = `user_images:${req.user.userId}:${JSON.stringify(req.query)}`;
    const cached = await redis.get(cacheKey);
    if (cached) {
      console.log('命中缓存');
      return res.json(JSON.parse(cached));
    }

    // 2. 解析查询参数
    const {
      page = 1,
      per_page = 20,
      category,
      sort = '-uploadDate',
      show_anonymous = 'false'
    } = req.query;

    // 3. 构建查询条件
    const query = { userId: req.user.userId };
    if (show_anonymous === 'true') {
      query.userId = { $in: [req.user.userId, 'anonymous'] };
    }
    if (category) {
      query.category = {
        $in: Array.isArray(category) ? category : [category]
      };
    }

    // 4. 执行查询
    const [images, total] = await Promise.all([
      Image.find(query)
        .sort(sort)
        .skip((page - 1) * per_page)
        .limit(parseInt(per_page))
        .select('-__v -_id')
        .lean(),
      Image.countDocuments(query)
    ]);

    // 5. 计算存储用量
    const storageUsage = await Image.aggregate([
      { $match: query },
      { $group: { _id: null, total: { $sum: "$size" } } }
    ]).then(result => result[0]?.total || 0);

    // 6. 构造响应
    const response = {
      success: true,
      data: images.map(img => ({
        ...img,
        thumbnail: img.url.replace('/uploads/', '/thumbnails/'),
        is_anonymous: img.userId === 'anonymous',
        editable: img.userId !== 'anonymous'
      })),
      pagination: {
        current_page: parseInt(page),
        per_page: parseInt(per_page),
        total,
        total_pages: Math.ceil(total / per_page),
        has_more: page * per_page < total
      },
      user_context: {
        total_images: total,
        storage_usage: storageUsage
      }
    };

    // 7. 设置缓存并返回
    await redis.setex(cacheKey, 300, JSON.stringify(response));
    res.json(response);

  } catch (error) {
    console.error('获取用户图片列表错误:', error);
    res.status(500).json({
      success: false,
      error: '获取图片列表失败',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 挂载路由
app.use('/api', router);
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// 修改保存路径逻辑

app.get('/', (req, res) => {
  res.send('Hello World');  // 根目录下简单显示helloworld进行测试
});

const PORT = process.env.PORT || 6006;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// 更新后的app.js部分 - 在路由之后添加错误处理
app.use((err, req, res, next) => {
  console.error('全局错误处理:', err.message);

  // 处理请求体过大错误
  if (err.type === 'entity.too.large' || err.name === 'PayloadTooLargeError') {
    return res.status(413).json({
      success: false,
      error: '请求体过大，请减少图片数量或压缩图片大小',
      details: '单次请求不能超过50MB'
    });
  }

  // 处理文件验证错误
  if (err.message.includes('不支持的文件格式') ||
    err.message.includes('文件大小超过')) {
    return res.status(400).json({ error: err.message });
  }

  // 处理Sharp错误
  if (err.message.includes('Vips')) {
    return res.status(500).json({ error: '图像处理失败' });
  }

  if (err) {
    // 其他错误
    console.error(err.stack);
    res.status(500).json({ error: '服务器错误' });
  }
});

module.exports = app; // 导出app以供测试使用