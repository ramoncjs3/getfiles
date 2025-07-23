package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// 客户端配置
type ClientConfig struct {
	ServerURL  string        `json:"server_url"`
	ClientID   string        `json:"client_id"`
	BatchSize  int           `json:"batch_size"`
	MaxRetries int           `json:"max_retries"`
	RetryDelay time.Duration `json:"retry_delay"`
	APIKey     string        `json:"api_key"`
}

// 传输状态
type TransferStatus struct {
	TotalFiles    int       `json:"total_files"`
	UploadedFiles int       `json:"uploaded_files"`
	TotalSize     int64     `json:"total_size"`
	UploadedSize  int64     `json:"uploaded_size"`
	Progress      float64   `json:"progress"`
	Status        string    `json:"status"`
	StartTime     time.Time `json:"start_time"`
	LastUpdate    time.Time `json:"last_update"`
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
	MD5      string `json:"md5"`
}

// 全局变量
var (
	config = ClientConfig{
		ServerURL:  "http://localhost:8080",
		ClientID:   generateClientID(),
		BatchSize:  10,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
		APIKey:     "GetFiles@2025#API$Secret!Key&Complex&Secure&Random&Token",
	}

	transferStatus = TransferStatus{
		Status:    "idle",
		StartTime: time.Now(),
	}

	uploadedFiles = make(map[string]bool)
	uploadedMutex sync.RWMutex
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "scan":
		runScan()
	case "upload":
		runUpload()
	case "scan-and-upload":
		runScanAndUpload()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("未知命令: %s\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("GetFiles 客户端")
	fmt.Println()
	fmt.Println("使用方法:")
	fmt.Println("  getfiles-client scan              - 扫描文件")
	fmt.Println("  getfiles-client upload            - 上传已扫描的文件")
	fmt.Println("  getfiles-client scan-and-upload  - 扫描并实时上传")
	fmt.Println("  getfiles-client help             - 显示此帮助信息")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  getfiles-client scan-and-upload")
}

func runScan() {
	fmt.Println("开始扫描文件...")
	files, err := scanFiles()
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	fmt.Printf("扫描完成，找到 %d 个文件\n", len(files))

	// 保存扫描结果
	if err := saveScanResults(files); err != nil {
		log.Printf("保存扫描结果失败: %v", err)
	}
}

func runUpload() {
	fmt.Println("开始上传文件...")

	// 加载扫描结果
	files, err := loadScanResults()
	if err != nil {
		log.Fatalf("加载扫描结果失败: %v", err)
	}

	// 上传文件
	for _, file := range files {
		if err := uploadFileOptimized(file); err != nil {
			fmt.Printf("上传文件失败 %s: %v\n", file.Path, err)
			continue
		}
		fmt.Printf("上传成功: %s\n", file.Path)
	}
}

func runScanAndUpload() {
	fmt.Println("开始扫描并实时上传...")

	// 获取系统信息
	fmt.Printf("客户端ID: %s\n", config.ClientID)
	fmt.Printf("系统: %s %s\n", getOS(), getArch())
	fmt.Printf("用户目录: %s\n", getUserDir())

	// 检查断点续传
	checkResume()

	// 开始扫描和上传
	files := scanAndUploadFilesOptimized()

	fmt.Printf("扫描和上传完成，共处理 %d 个文件\n", len(files))
}

// ==================== 优化的扫描上传系统 ====================

// 扫描上传配置
const (
	uploadWorkers   = 10               // 上传工作协程数
	uploadBatchSize = 5                // 上传批次大小
	uploadTimeout   = 60 * time.Second // 上传超时
	md5BufferSize   = 32 * 1024        // MD5计算缓冲区大小
)

// 优化的扫描上传函数
func scanAndUploadFilesOptimized() []FileInfo {
	var allFiles []FileInfo
	var mu sync.Mutex

	// 获取所有扫描目录
	scanDirs := getAllScanDirs()

	fmt.Printf("开始并发扫描上传，目录数: %d\n", len(scanDirs))
	fmt.Printf("上传工作协程数: %d\n", uploadWorkers)

	// 创建文件通道（更大的缓冲区）
	fileChan := make(chan FileInfo, 1000)

	// 启动多个上传协程
	var uploadWg sync.WaitGroup
	for i := 0; i < uploadWorkers; i++ {
		uploadWg.Add(1)
		go func(workerID int) {
			defer uploadWg.Done()
			uploadWorker(fileChan, workerID)
		}(i)
	}

	// 启动扫描协程
	var scanWg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)

	for _, scanDir := range scanDirs {
		scanWg.Add(1)
		go func(dir ScanDir) {
			defer scanWg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			files, err := scanDirectoryWithGodirwalk(dir.Path, dir.Priority, nil)
			if err != nil {
				fmt.Printf("扫描目录 %s 失败: %v\n", dir.Path, err)
				return
			}

			if len(files) > 0 {
				fmt.Printf("在 %s 中找到 %d 个文件\n", dir.Path, len(files))

				// 并发处理文件
				var fileWg sync.WaitGroup
				for _, file := range files {
					fileWg.Add(1)
					go func(f FileInfo) {
						defer fileWg.Done()

						// 快速计算MD5
						f.MD5 = calculateFileMD5Fast(f.Path)

						// 发送到上传通道
						fileChan <- f
					}(file)
				}
				fileWg.Wait()

				// 添加到总结果
				mu.Lock()
				allFiles = append(allFiles, files...)
				mu.Unlock()
			}
		}(scanDir)
	}

	// 等待扫描完成
	scanWg.Wait()
	close(fileChan)

	// 等待上传完成
	uploadWg.Wait()

	return allFiles
}

// 上传工作协程
func uploadWorker(fileChan <-chan FileInfo, workerID int) {
	var batch []FileInfo
	batchSize := uploadBatchSize

	for file := range fileChan {
		// 检查是否已上传
		uploadedMutex.RLock()
		alreadyUploaded := uploadedFiles[file.MD5]
		uploadedMutex.RUnlock()

		if alreadyUploaded {
			continue
		}

		batch = append(batch, file)

		if len(batch) >= batchSize {
			uploadBatchOptimized(batch, workerID)
			batch = batch[:0]
		}
	}

	// 上传剩余的文件
	if len(batch) > 0 {
		uploadBatchOptimized(batch, workerID)
	}
}

// 优化的批量上传
func uploadBatchOptimized(files []FileInfo, workerID int) {
	// 并发上传文件
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3) // 限制并发数

	for _, file := range files {
		wg.Add(1)
		go func(f FileInfo) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := uploadFileOptimized(f); err != nil {
				fmt.Printf("上传文件失败 %s: %v\n", f.Path, err)
				return
			}

			// 标记为已上传
			uploadedMutex.Lock()
			uploadedFiles[f.MD5] = true
			uploadedMutex.Unlock()

			// 更新传输状态
			transferStatus.UploadedFiles++
			transferStatus.UploadedSize += f.Size
			transferStatus.Progress = float64(transferStatus.UploadedFiles) / float64(transferStatus.TotalFiles) * 100
			transferStatus.LastUpdate = time.Now()

			fmt.Printf("[Worker-%d] 上传成功: %s (%s)\n", workerID, f.Path, formatSize(f.Size))
		}(file)
	}

	wg.Wait()
}

// 优化的单文件上传
func uploadFileOptimized(file FileInfo) error {
	// 打开文件
	f, err := os.Open(file.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	// 创建multipart表单
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加文件（使用更大的缓冲区）
	part, err := writer.CreateFormFile("file", filepath.Base(file.Path))
	if err != nil {
		return err
	}

	// 使用更大的缓冲区进行压缩
	gw := gzip.NewWriter(part)
	buffer := make([]byte, 64*1024) // 64KB缓冲区
	if _, err := io.CopyBuffer(gw, f, buffer); err != nil {
		return err
	}
	gw.Close()

	// 添加其他字段
	writer.WriteField("client_id", config.ClientID)
	writer.WriteField("hostname", getHostname())
	writer.WriteField("os", getOS())
	writer.WriteField("arch", getArch())
	writer.WriteField("user_dir", getUserDir())
	writer.WriteField("file_path", file.Path)
	writer.WriteField("file_size", fmt.Sprintf("%d", file.Size))
	writer.WriteField("file_md5", file.MD5)

	writer.Close()

	// 发送请求（使用连接池）
	url := fmt.Sprintf("%s/api/upload", config.ServerURL)
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+config.APIKey)

	// 使用优化的HTTP客户端
	client := &http.Client{
		Timeout: uploadTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("上传失败: %s - %s", resp.Status, string(body))
	}

	return nil
}

// 快速MD5计算
func calculateFileMD5Fast(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	hash := md5.New()
	buffer := make([]byte, md5BufferSize)

	if _, err := io.CopyBuffer(hash, f, buffer); err != nil {
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func checkResume() {
	fmt.Println("检查断点续传...")

	url := fmt.Sprintf("%s/api/resume/%s", config.ServerURL, config.ClientID)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("检查断点续传失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if uploaded, ok := result["uploaded_files"].([]interface{}); ok {
				fmt.Printf("发现 %d 个已上传文件\n", len(uploaded))
				for _, file := range uploaded {
					if filename, ok := file.(string); ok {
						uploadedMutex.Lock()
						uploadedFiles[filename] = true
						uploadedMutex.Unlock()
					}
				}
			}
		}
	}
}

func calculateFileMD5(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, f); err != nil {
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func generateClientID() string {
	hostname, _ := os.Hostname()
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s_%d", hostname, timestamp)
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getOS() string {
	return runtime.GOOS
}

func getArch() string {
	return runtime.GOARCH
}

func getUserDir() string {
	userDir, _ := os.UserHomeDir()
	return userDir
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

func saveScanResults(files []FileInfo) error {
	data, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("scan_results.json", data, 0644)
}

func loadScanResults() ([]FileInfo, error) {
	data, err := os.ReadFile("scan_results.json")
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	err = json.Unmarshal(data, &files)
	return files, err
}
