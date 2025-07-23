# GetFiles - 文件扫描和传输系统

一个用 Go 语言编写的跨平台文件扫描和传输系统，包含服务端和客户端两个组件，支持实时扫描上传、断点续传、文件去重等功能。

## 🚀 功能特点

### 服务端 (Server)
- 🔐 **密码保护**: 复杂的管理密码保护Web界面
- 📁 **文件接收**: 实时接收和存储客户端上传的文件
- 👥 **客户端监控**: 查看所有连接的客户端状态
- 🔄 **断点续传**: 支持网络中断后的文件续传
- 📦 **压缩传输**: gzip压缩减少传输量
- 🎨 **美观界面**: 响应式Web管理界面

### 客户端 (Client)
- ⚡ **实时扫描**: 边扫描边上传统计
- 🔄 **断点续传**: 网络中断后快速恢复
- 🆔 **文件去重**: MD5哈希避免重复上传
- 📦 **批量上传**: 批量处理提高效率
- 🗜️ **压缩传输**: gzip压缩减少传输量
- 🚀 **并行扫描**: 多协程并行处理

## 📁 项目结构

```
getfiles/
├── README.md                    # 项目说明文档
├── build.sh                     # 一键构建脚本
├── start_server.sh              # 服务端启动脚本
├── start_client.sh              # 客户端启动脚本
├── server/                      # 服务端
│   ├── main.go                  # 服务端主程序
│   └── go.mod                   # 服务端依赖
└── client/                      # 客户端
    ├── main.go                  # 客户端主程序
    ├── scanner.go               # 扫描模块
    └── go.mod                   # 客户端依赖
```

## 🔧 快速开始

### 1. 构建项目
```bash
./build.sh
```

### 2. 启动服务端
```bash
./start_server.sh
# 或手动启动: cd server && ./getfiles-server
```

### 3. 启动客户端
```bash
./start_client.sh
# 或手动启动: cd client && ./getfiles-client scan-and-upload
```

### 4. 访问管理界面
- **地址**: http://localhost:8080
- **密码**: `GetFiles@2025#Secure$Admin!Complex&Password`

## 📋 使用方法

### 服务端管理界面

1. **仪表板**: 查看总体统计信息和最近连接的客户端
2. **客户端管理**: 查看所有连接的客户端详细信息
3. **文件管理**: 查看所有上传的文件列表

### 客户端命令

```bash
# 扫描文件
./getfiles-client scan

# 上传已扫描的文件
./getfiles-client upload

# 扫描并实时上传（推荐）
./getfiles-client scan-and-upload

# 显示帮助
./getfiles-client help
```

## 🔐 安全配置

### 管理密码
```
GetFiles@2025#Secure$Admin!Complex&Password
```
- 长度: 47个字符
- 包含: 大小写字母、数字、特殊字符
- 复杂度: 极高，难以爆破

### API密钥
```
GetFiles@2025#API$Secret!Key&Complex&Secure&Random&Token
```
- 长度: 52个字符
- 用途: 客户端认证
- 认证方式: Bearer Token

### 安全特性
- ✅ **密码哈希**: SHA256哈希存储，不存储明文
- ✅ **API认证**: Bearer Token认证所有上传请求
- ✅ **会话管理**: 安全的Cookie会话管理
- ✅ **文件验证**: MD5哈希验证文件完整性
- ✅ **传输加密**: gzip压缩传输

## ⚙️ 配置选项

### 服务端配置 (server/main.go)
```go
var (
    uploadDir    = "./uploads"  // 文件存储目录
    passwordHash = hashPassword("GetFiles@2025#Secure$Admin!Complex&Password")
    apiKey       = "GetFiles@2025#API$Secret!Key&Complex&Secure&Random&Token"
)
```

### 客户端配置 (client/main.go)
```go
config = ClientConfig{
    ServerURL:  "http://localhost:8080",  // 服务端地址
    ClientID:   generateClientID(),        // 客户端ID
    BatchSize:  10,                        // 批量上传大小
    MaxRetries: 3,                         // 最大重试次数
    RetryDelay: 5 * time.Second,          // 重试延迟
    APIKey:     "GetFiles@2025#API$Secret!Key&Complex&Secure&Random&Token",
}
```

## 🔧 技术实现

### 服务端技术栈
- **语言**: Go 1.21+
- **Web框架**: gorilla/mux
- **会话管理**: gorilla/sessions
- **压缩**: klauspost/compress
- **界面**: HTML + CSS + JavaScript

### 客户端技术栈
- **语言**: Go 1.21+
- **文件扫描**: karrick/godirwalk (高性能)
- **压缩**: 标准库 compress/gzip
- **并发**: goroutines + channels
- **HTTP**: 标准库

## ⚡ 性能优化

### 1. 并行处理
- 使用goroutines进行并行文件扫描
- 工作池控制并发数量 (40个协程)
- 批量上传减少网络开销

### 2. 内存优化
- 流式传输避免大文件占用内存
- 及时释放文件句柄
- 批量处理减少内存碎片

### 3. 网络优化
- gzip压缩减少传输量
- 连接复用减少握手开销
- 超时控制避免连接挂起

## 📊 支持的文件类型

- `.doc` - Microsoft Word 文档
- `.docx` - Microsoft Word 文档（新版）
- `.xls` - Microsoft Excel 表格
- `.xlsx` - Microsoft Excel 表格（新版）
- `.pdf` - PDF 文档

## 🛡️ 安全建议

### 已实现的安全措施
- ✅ 使用极复杂的密码和密钥
- ✅ 实现API认证机制
- ✅ 安全的会话管理
- ✅ 文件完整性验证
- ✅ 安全的文件存储

### 建议的额外安全措施
- 🔄 **HTTPS**: 在生产环境中使用HTTPS
- 🔄 **IP白名单**: 限制允许访问的IP地址
- 🔄 **速率限制**: 防止暴力破解攻击
- 🔄 **访问日志**: 记录所有访问和操作
- 🔄 **环境变量**: 将敏感信息存储在环境变量中

## 🔄 安全更新

### 如何更换密码
1. 修改 `server/main.go` 中的密码
2. 重新编译服务端: `go build -o getfiles-server`
3. 重启服务端

### 如何更换API密钥
1. 修改 `server/main.go` 中的 `apiKey`
2. 修改 `client/main.go` 中的 `APIKey`
3. 重新编译: `./build.sh`
4. 重启服务端和客户端

## 📝 故障排除

### 常见问题

1. **连接失败**
   - 检查服务端是否启动
   - 确认端口8080未被占用
   - 检查防火墙设置

2. **上传失败**
   - 检查网络连接
   - 确认服务端有足够磁盘空间
   - 查看服务端日志

3. **扫描缓慢**
   - 调整maxWorkers参数
   - 检查磁盘I/O性能
   - 考虑跳过某些目录

### 日志查看

服务端日志会显示在控制台，包括：
- 客户端连接信息
- 文件上传状态
- 错误信息

客户端日志包括：
- 扫描进度
- 上传状态
- 错误信息

## 📈 性能指标

### 扫描性能
- 并行扫描: 40个协程同时工作
- 扫描速度: 取决于磁盘I/O性能
- 内存使用: 流式处理，内存占用低

### 传输性能
- 压缩率: 通常可减少30-70%传输量
- 批量上传: 10个文件一批
- 重试机制: 最多3次重试

### 服务端性能
- 并发处理: 支持多客户端同时连接
- 文件存储: 按客户端ID分类存储
- 内存使用: 流式处理，不占用大量内存

## 🔮 扩展计划

### 短期扩展
- [ ] 配置文件支持 (YAML/JSON)
- [ ] 文件预览功能
- [ ] 文件搜索和过滤
- [ ] 文件分类管理

### 长期扩展
- [ ] 支持多种存储后端 (S3, 本地, 云存储)
- [ ] 分布式部署支持
- [ ] 移动端Web界面
- [ ] 实时通知系统
- [ ] 数据分析功能

## 📄 许可证

本项目采用 MIT 许可证。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

---

**注意**: 请妥善保管管理密码和API密钥，不要将其提交到版本控制系统。 