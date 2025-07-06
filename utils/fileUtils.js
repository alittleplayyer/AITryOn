const path = require('path');
const fs = require('fs').promises;

// 定义上传根目录
const UPLOAD_ROOT = path.join(process.cwd(), 'uploads');

// 获取用户目录路径
const getUserDir = (userId) => {
  return path.join(UPLOAD_ROOT, userId);
};

// 确保目录存在（如果存在直接返回）
const ensureCategoryDir = async (userId, category) => {
  const categoryDir = path.join(getUserDir(userId), category);
  
  try {
    await fs.access(categoryDir);
    return categoryDir;
  } catch {
    return createCategoryDir(userId, category);
  }
};

// 创建用户目录结构
const createUserDir = async (userId) => {
  const userDir = getUserDir(userId);
  
  try {
    await fs.mkdir(userDir, { recursive: true });
    
    // 创建默认分类目录
    const categories = ['clothes', 'char', 'vton_results', 'favorites'];
    await Promise.all(categories.map(category => 
      fs.mkdir(path.join(userDir, category), { recursive: true })
    ));
    
    return userDir;
  } catch (error) {
    console.error(`创建用户目录失败: ${userDir}`, error);
    throw error;
  }
};

module.exports = {
  UPLOAD_ROOT,
  getUserDir,
  ensureUserDir,
  createUserDir
};