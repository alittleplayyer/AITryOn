// routes/auth.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');

// 用户注册
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // 基础验证
    if (!username || !email || !password) {
      return res.status(400).json({ message: '所有字段都是必填项' });
    }

    // 检查用户是否已存在
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: '用户名或邮箱已被使用' });
    }

    // 创建新用户
    const user = new User({ username, email, password });
    await user.save();
    
    res.status(201).json({ message: '用户注册成功' });
  } catch (err) {
    res.status(500).json({ message: '服务器错误' });
  }
});

// routes/auth.js
const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  try {
    const { credential, password } = req.body; // 可以是用户名或邮箱
    
    // 查找用户
    const user = await User.findOne({ 
      $or: [{ username: credential }, { email: credential }]
    });
    
    if (!user) {
      return res.status(401).json({ message: '无效的凭据' });
    }
    
    // 验证密码
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: '密码错误' });
    }
    
    // 生成JWT令牌
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ message: '登录失败' });
  }
});