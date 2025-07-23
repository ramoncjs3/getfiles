package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/karrick/godirwalk"
)

// ==================== 配置常量 ====================

// 扫描配置
const (
	// 超时设置
	priorityScanTimeout = 20 * time.Second // 优先目录超时
	normalScanTimeout   = 8 * time.Second  // 普通目录超时
	quickScanTimeout    = 3 * time.Second  // 快速扫描超时

	// 并发设置
	maxWorkers = 50 // 最大工作协程数

	// 扫描深度
	maxScanDepth = 8 // 最大扫描深度
)

// ==================== 文件类型配置 ====================

// 目标文件扩展名
var targetExtensions = map[string]bool{
	".doc":  true,
	".docx": true,
	".xls":  true,
	".xlsx": true,
	".pdf":  true,
}

// ==================== 目录跳过配置 ====================

// 系统目录跳过映射
var systemSkipDirs = map[string]map[string]bool{
	"windows": {
		"$RECYCLE.BIN":              true,
		"System Volume Information": true,
		"Windows":                   true,
		"Program Files":             true,
		"Program Files (x86)":       true,
		"$Recycle.Bin":              true,
		"Config.Msi":                true,
		"MSOCache":                  true,
		"Recovery":                  true,
		"$WinREAgent":               true,
	},
	"darwin": {
		".Trashes":        true,
		".Spotlight-V100": true,
		".fseventsd":      true,
		".DS_Store":       true,
		"System":          true,
		"Applications":    true,
		"Volumes":         true,
		"private":         true,
		"bin":             true,
		"sbin":            true,
	},
	"linux": {
		".Trash": true,
		".cache": true,
		".local": true,
		"proc":   true,
		"sys":    true,
		"dev":    true,
		"run":    true,
		"tmp":    true,
		"var":    true,
		"boot":   true,
	},
}

// 通用跳过目录
var commonSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".svn":         true,
	"__pycache__":  true,
	"Thumbs.db":    true,
	".gitignore":   true,
	".DS_Store":    true,
}

// ==================== 核心扫描逻辑 ====================

// 扫描优先级
type ScanPriority int

const (
	PriorityHigh   ScanPriority = 1 // 高优先级：用户文档目录
	PriorityMedium ScanPriority = 2 // 中优先级：用户其他目录
	PriorityLow    ScanPriority = 3 // 低优先级：系统目录
)

// 扫描目录信息
type ScanDir struct {
	Path     string
	Priority ScanPriority
}

// 检查文件扩展名
func hasTargetExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return targetExtensions[ext]
}

// 检查是否应该跳过目录
func shouldSkipDir(dirName string) bool {
	// 检查通用跳过目录
	if commonSkipDirs[dirName] {
		return true
	}

	// 检查系统特定跳过目录
	if systemDirs, exists := systemSkipDirs[runtime.GOOS]; exists {
		if systemDirs[dirName] {
			return true
		}
	}

	return false
}

// 获取扫描超时时间
func getScanTimeout(priority ScanPriority) time.Duration {
	switch priority {
	case PriorityHigh:
		return priorityScanTimeout
	case PriorityMedium:
		return normalScanTimeout
	default:
		return quickScanTimeout
	}
}

// ==================== 目录获取逻辑 ====================

// 获取高优先级扫描目录（用户文档目录）
func getHighPriorityDirs() []string {
	userDir, err := os.UserHomeDir()
	if err != nil {
		return []string{}
	}

	var dirs []string

	// 根据操作系统添加不同的优先目录
	switch runtime.GOOS {
	case "windows":
		dirs = append(dirs,
			filepath.Join(userDir, "Desktop"),
			filepath.Join(userDir, "Documents"),
			filepath.Join(userDir, "Downloads"),
			filepath.Join(userDir, "Pictures"),
		)
	case "darwin": // macOS
		dirs = append(dirs,
			filepath.Join(userDir, "Desktop"),
			filepath.Join(userDir, "Documents"),
			filepath.Join(userDir, "Downloads"),
			filepath.Join(userDir, "Pictures"),
		)
	default: // Linux
		dirs = append(dirs,
			filepath.Join(userDir, "Desktop"),
			filepath.Join(userDir, "Documents"),
			filepath.Join(userDir, "Downloads"),
			filepath.Join(userDir, "Pictures"),
		)
	}

	// 过滤掉不存在的目录
	var validDirs []string
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			validDirs = append(validDirs, dir)
		}
	}

	return validDirs
}

// 获取中优先级扫描目录（用户其他目录）
func getMediumPriorityDirs() []string {
	userDir, err := os.UserHomeDir()
	if err != nil {
		return []string{}
	}

	var dirs []string

	switch runtime.GOOS {
	case "windows":
		dirs = append(dirs,
			filepath.Join(userDir, "Music"),
			filepath.Join(userDir, "Videos"),
			filepath.Join(userDir, "Favorites"),
		)
	case "darwin":
		dirs = append(dirs,
			filepath.Join(userDir, "Music"),
			filepath.Join(userDir, "Movies"),
			filepath.Join(userDir, "Public"),
		)
	default:
		dirs = append(dirs,
			filepath.Join(userDir, "Music"),
			filepath.Join(userDir, "Videos"),
			filepath.Join(userDir, "Public"),
		)
	}

	// 过滤掉不存在的目录
	var validDirs []string
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			validDirs = append(validDirs, dir)
		}
	}

	return validDirs
}

// 获取低优先级扫描目录（系统目录）
func getLowPriorityDirs() []string {
	var dirs []string

	switch runtime.GOOS {
	case "windows":
		// Windows盘符扫描
		for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				dirs = append(dirs, drivePath)
			}
		}
	case "darwin":
		// macOS系统目录
		systemDirs := []string{"/usr", "/opt"}
		for _, dir := range systemDirs {
			if _, err := os.Stat(dir); err == nil {
				dirs = append(dirs, dir)
			}
		}
	case "linux":
		// Linux挂载点
		if data, err := os.ReadFile("/proc/mounts"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					mountPoint := fields[1]
					if !strings.HasPrefix(mountPoint, "/proc") &&
						!strings.HasPrefix(mountPoint, "/sys") &&
						!strings.HasPrefix(mountPoint, "/dev") &&
						!strings.HasPrefix(mountPoint, "/run") &&
						mountPoint != "/" &&
						mountPoint != "/tmp" &&
						mountPoint != "/var" {
						dirs = append(dirs, mountPoint)
					}
				}
			}
		}
	}

	return dirs
}

// 获取所有扫描目录
func getAllScanDirs() []ScanDir {
	var scanDirs []ScanDir

	// 高优先级目录
	highPriorityDirs := getHighPriorityDirs()
	for _, dir := range highPriorityDirs {
		scanDirs = append(scanDirs, ScanDir{Path: dir, Priority: PriorityHigh})
	}

	// 中优先级目录
	mediumPriorityDirs := getMediumPriorityDirs()
	for _, dir := range mediumPriorityDirs {
		scanDirs = append(scanDirs, ScanDir{Path: dir, Priority: PriorityMedium})
	}

	// 低优先级目录
	lowPriorityDirs := getLowPriorityDirs()
	for _, dir := range lowPriorityDirs {
		scanDirs = append(scanDirs, ScanDir{Path: dir, Priority: PriorityLow})
	}

	return scanDirs
}

// 扫描文件（优化版）
func scanFiles() ([]FileInfo, error) {
	var allFiles []FileInfo
	var mu sync.Mutex

	// 预分配内存
	allFiles = make([]FileInfo, 0, 10000)

	// 获取所有扫描目录
	scanDirs := getAllScanDirs()

	fmt.Printf("开始扫描，优先目录: %d 个，全盘目录: %d 个\n",
		len(getHighPriorityDirs()), len(scanDirs)-len(getHighPriorityDirs()))
	fmt.Printf("扫描文件类型: %s\n", strings.Join([]string{".doc", ".docx", ".xls", ".xlsx", ".pdf"}, ", "))
	fmt.Printf("系统: %s\n", runtime.GOOS)
	fmt.Printf("工作协程数: %d\n", maxWorkers)

	// 创建上下文用于取消操作
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 使用工作池进行并行扫描
	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	// 创建结果通道
	resultChan := make(chan []FileInfo, maxWorkers)

	// 启动结果收集协程
	go func() {
		for files := range resultChan {
			mu.Lock()
			allFiles = append(allFiles, files...)
			mu.Unlock()
		}
	}()

	// 并行扫描所有目录
	for _, scanDir := range scanDirs {
		wg.Add(1)
		go func(dir ScanDir) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			files, err := scanDirectoryWithGodirwalk(dir.Path, dir.Priority, ctx)
			if err != nil {
				fmt.Printf("扫描目录 %s 时出错: %v\n", dir.Path, err)
				return
			}

			if len(files) > 0 {
				fmt.Printf("在 %s 中找到 %d 个文件\n", dir.Path, len(files))
				resultChan <- files
			}
		}(scanDir)
	}

	// 等待所有扫描完成
	wg.Wait()
	close(resultChan)

	return allFiles, nil
}

// 使用 godirwalk 扫描单个目录（优化版）
func scanDirectoryWithGodirwalk(dir string, priority ScanPriority, ctx context.Context) ([]FileInfo, error) {
	var files []FileInfo
	files = make([]FileInfo, 0, 1000) // 预分配内存

	// 获取超时时间
	timeout := getScanTimeout(priority)

	// 创建扫描选项
	options := &godirwalk.Options{
		Callback: func(osPathname string, de *godirwalk.Dirent) error {
			// 检查上下文是否已取消
			if ctx != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
			}

			// 跳过目录
			if de.IsDir() {
				// 检查是否应该跳过此目录
				dirName := filepath.Base(osPathname)
				if shouldSkipDir(dirName) {
					return godirwalk.SkipThis
				}
				return nil
			}

			// 使用优化的扩展名检查
			if hasTargetExtension(osPathname) {
				// 计算相对路径
				relative, _ := filepath.Rel(dir, osPathname)

				// 获取文件信息（非阻塞）
				info, err := os.Stat(osPathname)
				if err != nil {
					// 如果无法获取文件信息，跳过此文件
					return nil
				}

				// 获取目录名和扩展名
				dirName := filepath.Dir(osPathname)
				ext := strings.ToLower(filepath.Ext(osPathname))

				file := FileInfo{
					Path:     osPathname,
					Size:     info.Size(),
					ModTime:  info.ModTime().Format("2006-01-02 15:04:05"),
					Relative: relative,
					Priority: int(priority), // 转换为int类型
					Dir:      dirName,
					Ext:      ext,
				}

				// 直接添加到结果（避免通道开销）
				files = append(files, file)
			}

			return nil
		},
		ErrorCallback: func(osPathname string, err error) godirwalk.ErrorAction {
			// 对于访问错误，跳过该目录继续扫描
			return godirwalk.SkipNode
		},
		Unsorted: true, // 不排序以提高速度
	}

	// 使用超时上下文
	scanCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 在goroutine中执行扫描，以便可以超时
	scanDone := make(chan error, 1)
	go func() {
		err := godirwalk.Walk(dir, options)
		scanDone <- err
	}()

	// 等待扫描完成或超时
	select {
	case err := <-scanDone:
		if err != nil {
			fmt.Printf("扫描目录 %s 时出错: %v\n", dir, err)
		}
		return files, err
	case <-scanCtx.Done():
		fmt.Printf("扫描目录 %s 超时 (%s)\n", dir, timeout)
		return files, nil
	}
}
