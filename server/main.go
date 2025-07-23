package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// 全局变量
var (
	store        *sessions.CookieStore
	uploadDir    = "./uploads"
	passwordHash string
	apiKey       = "GetFiles@2025#API$Secret!Key&Complex&Secure&Random&Token"
	clients      = make(map[string]*ClientInfo)
	clientsMutex sync.RWMutex
)

// 客户端信息
type ClientInfo struct {
	ID         string     `json:"id"`
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os"`
	Arch       string     `json:"arch"`
	UserDir    string     `json:"user_dir"`
	LastSeen   time.Time  `json:"last_seen"`
	Files      []FileInfo `json:"files"`
	TotalSize  int64      `json:"total_size"`
	UploadedAt time.Time  `json:"uploaded_at"`
}

// 文件信息
type FileInfo struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	ModTime  string `json:"mod_time"`
	Relative string `json:"relative"`
	Priority int    `json:"priority"`
	Dir      string `json:"dir"`
	Ext      string `json:"ext"`
	ClientID string `json:"client_id"`
}

// 传输状态
type TransferStatus struct {
	ClientID      string    `json:"client_id"`
	TotalFiles    int       `json:"total_files"`
	UploadedFiles int       `json:"uploaded_files"`
	TotalSize     int64     `json:"total_size"`
	UploadedSize  int64     `json:"uploaded_size"`
	Status        string    `json:"status"` // "uploading", "completed", "failed"
	StartTime     time.Time `json:"start_time"`
	LastUpdate    time.Time `json:"last_update"`
}

func main() {
	// 初始化
	initServer()

	// 创建路由
	r := mux.NewRouter()

	// 静态文件服务
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 认证中间件
	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "session-name")
			if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		}
	}

	// 路由设置
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/", authMiddleware(dashboardHandler))
	r.HandleFunc("/clients", authMiddleware(clientsHandler))
	r.HandleFunc("/files", authMiddleware(filesHandler))
	r.HandleFunc("/api/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/api/status/{clientID}", statusHandler).Methods("GET")
	r.HandleFunc("/api/resume/{clientID}", resumeHandler).Methods("POST")

	// 启动服务器
	fmt.Println("服务器启动在 :8080")
	fmt.Println("访问 http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func initServer() {
	// 创建上传目录
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Fatal("创建上传目录失败:", err)
	}

	// 初始化session store (使用复杂的会话密钥)
	store = sessions.NewCookieStore([]byte("GetFiles@2025#Session$Secret!Key&Complex&Secure&Random&Bytes"))

	// 设置复杂的管理密码 (包含大小写字母、数字、特殊字符)
	// 密码: GetFiles@2025#Secure$Admin!Complex&Password
	passwordHash = hashPassword("GetFiles@2025#Secure$Admin!Complex&Password")

	// 创建静态文件目录
	if err := os.MkdirAll("static", 0755); err != nil {
		log.Fatal("创建静态文件目录失败:", err)
	}

	// 创建静态文件
	createStaticFiles()
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func createStaticFiles() {
	// 创建CSS文件
	css := `
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    padding: 20px;
}
.header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #eee;
}
.nav {
    display: flex;
    justify-content: center;
    gap: 20px;
    margin-bottom: 30px;
}
.nav a {
    padding: 10px 20px;
    text-decoration: none;
    color: #333;
    border-radius: 5px;
    transition: background-color 0.3s;
}
.nav a:hover {
    background-color: #f0f0f0;
}
.nav a.active {
    background-color: #007bff;
    color: white;
}
.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.stat-card {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    text-align: center;
}
.stat-card h3 {
    margin: 0 0 10px 0;
    color: #007bff;
}
.stat-card .number {
    font-size: 2em;
    font-weight: bold;
    color: #333;
}
.client-list, .file-list {
    background: white;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}
.client-item, .file-item {
    padding: 15px;
    border-bottom: 1px solid #eee;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.client-item:hover, .file-item:hover {
    background-color: #f8f9fa;
}
.client-info, .file-info {
    flex: 1;
}
.client-name, .file-name {
    font-weight: bold;
    margin-bottom: 5px;
}
.client-details, .file-details {
    font-size: 0.9em;
    color: #666;
}
.file-size {
    color: #007bff;
    font-weight: bold;
}
.login-form {
    max-width: 400px;
    margin: 100px auto;
    padding: 30px;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}
.form-group {
    margin-bottom: 20px;
}
.form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}
.form-group input {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 16px;
}
.btn {
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;
}
.btn-primary {
    background-color: #007bff;
    color: white;
}
.btn-primary:hover {
    background-color: #0056b3;
}
.alert {
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.alert-danger {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}
`

	os.WriteFile("static/style.css", []byte(css), 0644)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		password := r.FormValue("password")
		if hashPassword(password) == passwordHash {
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Error(w, "密码错误", http.StatusUnauthorized)
		return
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>登录 - GetFiles 服务端</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="login-form">
        <h2>GetFiles 服务端</h2>
        <form method="POST">
            <div class="form-group">
                <label for="password">密码:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">登录</button>
        </form>
    </div>
</body>
</html>`

	t, _ := template.New("login").Parse(tmpl)
	t.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	clientsMutex.RLock()
	defer clientsMutex.RUnlock()

	var totalFiles, totalSize int64
	var totalClients int

	for _, client := range clients {
		totalFiles += int64(len(client.Files))
		totalSize += client.TotalSize
		totalClients++
	}

	data := struct {
		TotalClients int
		TotalFiles   int64
		TotalSize    int64
		Clients      map[string]*ClientInfo
	}{
		TotalClients: totalClients,
		TotalFiles:   totalFiles,
		TotalSize:    totalSize,
		Clients:      clients,
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>仪表板 - GetFiles 服务端</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>GetFiles 服务端</h1>
            <p>文件扫描和传输管理系统</p>
        </div>
        
        <div class="nav">
            <a href="/" class="active">仪表板</a>
            <a href="/clients">客户端</a>
            <a href="/files">文件</a>
            <a href="/logout">退出</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>客户端数量</h3>
                <div class="number">{{.TotalClients}}</div>
            </div>
            <div class="stat-card">
                <h3>文件总数</h3>
                <div class="number">{{.TotalFiles}}</div>
            </div>
            <div class="stat-card">
                <h3>总大小</h3>
                <div class="number">{{formatSize .TotalSize}}</div>
            </div>
        </div>
        
        <h2>最近连接的客户端</h2>
        <div class="client-list">
            {{range .Clients}}
            <div class="client-item">
                <div class="client-info">
                    <div class="client-name">{{.Hostname}}</div>
                    <div class="client-details">
                        {{.OS}} ({{.Arch}}) | {{len .Files}} 个文件 | {{formatSize .TotalSize}} | 
                        最后更新: {{.LastSeen.Format "2006-01-02 15:04:05"}}
                    </div>
                </div>
            </div>
            {{else}}
            <div class="client-item">
                <div class="client-info">
                    <div class="client-name">暂无客户端连接</div>
                </div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`

	t, _ := template.New("dashboard").Funcs(template.FuncMap{
		"formatSize": formatSize,
	}).Parse(tmpl)
	t.Execute(w, data)
}

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	clientsMutex.RLock()
	defer clientsMutex.RUnlock()

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>客户端 - GetFiles 服务端</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>客户端管理</h1>
        </div>
        
        <div class="nav">
            <a href="/">仪表板</a>
            <a href="/clients" class="active">客户端</a>
            <a href="/files">文件</a>
            <a href="/logout">退出</a>
        </div>
        
        <div class="client-list">
            {{range .Clients}}
            <div class="client-item">
                <div class="client-info">
                    <div class="client-name">{{.Hostname}} ({{.ID}})</div>
                    <div class="client-details">
                        系统: {{.OS}} {{.Arch}}<br>
                        用户目录: {{.UserDir}}<br>
                        文件数量: {{len .Files}}<br>
                        总大小: {{formatSize .TotalSize}}<br>
                        上传时间: {{.UploadedAt.Format "2006-01-02 15:04:05"}}<br>
                        最后更新: {{.LastSeen.Format "2006-01-02 15:04:05"}}
                    </div>
                </div>
            </div>
            {{else}}
            <div class="client-item">
                <div class="client-info">
                    <div class="client-name">暂无客户端连接</div>
                </div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`

	t, _ := template.New("clients").Funcs(template.FuncMap{
		"formatSize": formatSize,
	}).Parse(tmpl)
	t.Execute(w, clients)
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	clientsMutex.RLock()
	defer clientsMutex.RUnlock()

	var allFiles []FileInfo
	for _, client := range clients {
		allFiles = append(allFiles, client.Files...)
	}

	// 按文件大小排序
	sort.Slice(allFiles, func(i, j int) bool {
		return allFiles[i].Size > allFiles[j].Size
	})

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>文件 - GetFiles 服务端</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>文件列表</h1>
        </div>
        
        <div class="nav">
            <a href="/">仪表板</a>
            <a href="/clients">客户端</a>
            <a href="/files" class="active">文件</a>
            <a href="/logout">退出</a>
        </div>
        
        <div class="file-list">
            {{range .Files}}
            <div class="file-item">
                <div class="file-info">
                    <div class="file-name">{{.Path}}</div>
                    <div class="file-details">
                        客户端: {{.ClientID}} | 
                        大小: <span class="file-size">{{formatSize .Size}}</span> | 
                        修改时间: {{.ModTime}} | 
                        类型: {{.Ext}}
                    </div>
                </div>
            </div>
            {{else}}
            <div class="file-item">
                <div class="file-info">
                    <div class="file-name">暂无文件</div>
                </div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`

	data := struct {
		Files []FileInfo
	}{
		Files: allFiles,
	}

	t, _ := template.New("files").Funcs(template.FuncMap{
		"formatSize": formatSize,
	}).Parse(tmpl)
	t.Execute(w, data)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// 验证API密钥
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "缺少Authorization头", http.StatusUnauthorized)
		return
	}

	// 检查Bearer token格式
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "无效的Authorization格式", http.StatusUnauthorized)
		return
	}

	// 验证API密钥
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != apiKey {
		http.Error(w, "无效的API密钥", http.StatusUnauthorized)
		return
	}

	// 检查Content-Type
	if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		http.Error(w, "无效的Content-Type", http.StatusBadRequest)
		return
	}

	// 解析multipart表单
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "解析表单失败", http.StatusBadRequest)
		return
	}

	// 获取客户端信息
	clientID := r.FormValue("client_id")
	if clientID == "" {
		http.Error(w, "缺少client_id", http.StatusBadRequest)
		return
	}

	// 获取文件
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "获取文件失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 创建客户端目录
	clientDir := filepath.Join(uploadDir, clientID)
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		http.Error(w, "创建目录失败", http.StatusInternalServerError)
		return
	}

	// 保存文件
	filePath := filepath.Join(clientDir, header.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "创建文件失败", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// 复制文件内容
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "保存文件失败", http.StatusInternalServerError)
		return
	}

	// 更新客户端信息
	clientsMutex.Lock()
	if client, exists := clients[clientID]; exists {
		client.LastSeen = time.Now()
	} else {
		clients[clientID] = &ClientInfo{
			ID:         clientID,
			Hostname:   r.FormValue("hostname"),
			OS:         r.FormValue("os"),
			Arch:       r.FormValue("arch"),
			UserDir:    r.FormValue("user_dir"),
			LastSeen:   time.Now(),
			UploadedAt: time.Now(),
		}
	}
	clientsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("文件上传成功"))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["clientID"]

	clientsMutex.RLock()
	client, exists := clients[clientID]
	clientsMutex.RUnlock()

	if !exists {
		http.Error(w, "客户端不存在", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

func resumeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["clientID"]

	// 获取已上传的文件列表
	clientDir := filepath.Join(uploadDir, clientID)
	var uploadedFiles []string

	if info, err := os.Stat(clientDir); err == nil && info.IsDir() {
		if files, err := os.ReadDir(clientDir); err == nil {
			for _, file := range files {
				if !file.IsDir() {
					uploadedFiles = append(uploadedFiles, file.Name())
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uploaded_files": uploadedFiles,
	})
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
