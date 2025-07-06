const jwt = require('jsonwebtoken');

exports.authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: '缺少认证令牌' });
  }
  
  try {
    // 从环境变量中获取JWT密钥
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      userId: decoded.userId,
      role: decoded.role
    };
    next();
  } catch (err) {
    console.error('令牌验证错误:', err);
    res.status(401).json({ error: '无效或过期的令牌' });
  }
};