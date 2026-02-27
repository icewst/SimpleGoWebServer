package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/*
最终版功能汇总（按你所有最新要求）：

A) Web 静态服务
- 发布当前目录
- / -> /index.html
- 基础路径越界防护（按路径段禁止 ".." + Rel 校验）

B) 配置文件：./config.json
- 启动必须读取 config.json 获取 port
- config.json 不存在：自动生成（带 _comment 注释）并退出
- 默认 port = 30080
- 只新增一个参数：install_systemd，默认 true（写入 config.json）

C) 内置方案一（systemd）
- install_systemd=true 且非 systemd 子进程时：
  - 写 /etc/systemd/system/serve-static.service
  - systemctl daemon-reload / enable / restart
  - 为避免重复运行/端口冲突：会先尝试 systemctl stop serve-static（忽略失败）
- unit 注入 Environment=SERVE_SYSTEMD=1，避免安装循环

D) 程序运行后释放两个脚本（同目录）并默认可执行：
- start_service.sh
- stop_service.sh
脚本要求：兼容 install_systemd=true / false，并都能正常使用
- 脚本从 config.json 解析 install_systemd：
  - true：优先 systemctl start/stop serve-static；若 unit 不存在则先执行 ./serve 安装；若无 systemctl 则降级为 PID 模式
  - false：使用 nohup + pidfile 方式启动/停止（serve.pid / serve.out.log）
- 非 systemd PID 启动时脚本会 export SERVE_SYSTEMD=1，避免 install_systemd=true 的安装逻辑干扰（即使 config 写了 true）
*/

const (
	configFileName = "config.json"

	// 默认端口：避免浏览器 UNSAFE_PORT（10080 在部分浏览器/策略下会被拦截）
	defaultPort = 30080

	// systemd 服务名固定
	defaultServiceName = "serve-static"

	// systemd 安装循环防护：unit 内设置 Environment=SERVE_SYSTEMD=1
	systemdEnvKey = "SERVE_SYSTEMD"
	systemdEnvVal = "1"

	// 生成脚本/运行文件
	startScriptName = "start_service.sh"
	stopScriptName  = "stop_service.sh"
	pidFileName     = "serve.pid"
	outLogName      = "serve.out.log"
)

// 只新增 install_systemd 一个参数
type Config struct {
	Comment        any  `json:"_comment,omitempty"`
	Port           int  `json:"port"`
	InstallSystemd bool `json:"install_systemd"`
}

func main() {
	rootAbs, err := filepath.Abs(".")
	if err != nil {
		fatalCN("启动失败：无法获取当前目录", err)
	}

	// 先生成 start/stop 脚本（每次运行覆盖写+chmod）
	if err := writeHelperScripts(rootAbs); err != nil {
		fatalCN("启动失败：生成启动/停止脚本失败", err)
	}

	cfg, status, err := readOrInitConfig(configFileName)
	if err != nil {
		fatalCN("启动失败：配置文件读取/解析失败", err)
	}
	if status == "initialized" {
		log.Printf("已生成默认 %s（含注释，默认 port=%d，install_systemd=true）。请确认后重新运行以启动服务。", configFileName, defaultPort)
		log.Printf("已生成脚本：%s / %s（已加执行权限）", startScriptName, stopScriptName)
		return
	}

	if err := validatePort(cfg.Port); err != nil {
		fatalCN("启动失败：端口配置不合法", err)
	}

	// ---- 内置 systemd 安装（方案一） ----
	if cfg.InstallSystemd && os.Getenv(systemdEnvKey) != systemdEnvVal {
		if err := ensureSystemdService(rootAbs); err != nil {
			fatalCN("启动失败：安装/启动 systemd 服务失败", err)
		}
		log.Printf("已安装并启动 systemd 服务：%s。以后用 systemctl/journalctl 管理。", defaultServiceName)
		log.Printf("也可以用脚本：./%s 或 ./%s（脚本会按 config.json 的 install_systemd 自动选择方式）", startScriptName, stopScriptName)
		return
	}

	// ---- 正常启动 HTTP 静态服务 ----
	handler := newStaticHandler(rootAbs)

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           loggingMiddleware(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("根目录：%s", rootAbs)
	log.Printf("配置文件：%s（port=%d）", filepath.Join(rootAbs, configFileName), cfg.Port)
	log.Printf("监听地址：http://%s/", addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatalCN("启动失败：端口监听失败", err)
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalCN("启动失败：HTTP 服务运行异常", err)
	}
}

// ---------------- 脚本生成（按 install_systemd=true/false 均可用） ----------------

func writeHelperScripts(dir string) error {
	startPath := filepath.Join(dir, startScriptName)
	stopPath := filepath.Join(dir, stopScriptName)

	startContent := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

BIN="./serve"
CFG="./%s"
SERVICE_NAME="%s"
PID_FILE="%s"
LOG_FILE="%s"

# 从 config.json 里取 install_systemd（不依赖 jq）
# 只解析 true/false，没找到就当 false
get_install_systemd() {
  if [[ ! -f "$CFG" ]]; then
    echo "false"
    return
  fi
  local v
  v="$(grep -Eo '"install_systemd"[[:space:]]*:[[:space:]]*(true|false)' "$CFG" 2>/dev/null \
      | head -n 1 \
      | sed -E 's/.*:(.*)/\1/' \
      | tr -d '[:space:]' || true)"
  if [[ "$v" == "true" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

have_systemctl() { command -v systemctl >/dev/null 2>&1; }

unit_exists() {
  [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] || systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}\.service"
}

is_running_pid() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

start_pid_mode() {
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if is_running_pid "$pid"; then
      echo "已在运行（PID=$pid）"
      exit 0
    fi
    rm -f "$PID_FILE"
  fi

  if [[ ! -x "$BIN" ]]; then
    echo "错误：未找到可执行文件或不可执行：$BIN"
    exit 1
  fi

  # 避免 install_systemd=true 时触发安装循环：非 systemd 方式启动时直接跳过安装逻辑
  export %s=%s
  nohup "$BIN" >>"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "已启动（PID 模式），PID=$(cat "$PID_FILE")，日志：$LOG_FILE"
}

INSTALL_SYSTEMD="$(get_install_systemd)"

if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
  if have_systemctl; then
    if unit_exists; then
      echo "config: install_systemd=true -> 使用 systemctl 启动 ${SERVICE_NAME}"
      systemctl start "$SERVICE_NAME"
      systemctl status "$SERVICE_NAME" --no-pager || true
      exit 0
    else
      echo "未检测到 ${SERVICE_NAME}.service，执行 $BIN 安装并启动 systemd 服务..."
      "$BIN" || true
      systemctl status "$SERVICE_NAME" --no-pager || true
      exit 0
    fi
  else
    echo "config: install_systemd=true，但系统无 systemctl -> 自动降级为 PID 模式启动"
    start_pid_mode
    exit 0
  fi
fi

echo "config: install_systemd=false -> 使用 PID 模式启动"
start_pid_mode
`, configFileName, defaultServiceName, pidFileName, outLogName, systemdEnvKey, systemdEnvVal)

	stopContent := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

CFG="./%s"
SERVICE_NAME="%s"
PID_FILE="%s"

get_install_systemd() {
  if [[ ! -f "$CFG" ]]; then
    echo "false"
    return
  fi
  local v
  v="$(grep -Eo '"install_systemd"[[:space:]]*:[[:space:]]*(true|false)' "$CFG" 2>/dev/null \
      | head -n 1 \
      | sed -E 's/.*:(.*)/\1/' \
      | tr -d '[:space:]' || true)"
  if [[ "$v" == "true" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

have_systemctl() { command -v systemctl >/dev/null 2>&1; }

unit_exists() {
  [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] || systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}\.service"
}

is_running_pid() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

stop_pid_mode() {
  if [[ ! -f "$PID_FILE" ]]; then
    echo "未找到 PID 文件：$PID_FILE（可能未以 PID 模式启动）"
    exit 0
  fi

  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if ! is_running_pid "$pid"; then
    echo "进程不存在或已退出（PID=$pid），清理 PID 文件"
    rm -f "$PID_FILE"
    exit 0
  fi

  echo "停止进程（PID=$pid）..."
  kill "$pid" || true

  for i in {1..50}; do
    if ! is_running_pid "$pid"; then
      rm -f "$PID_FILE"
      echo "已停止"
      exit 0
    fi
    sleep 0.1
  done

  echo "未在 5 秒内退出，发送 SIGKILL..."
  kill -9 "$pid" || true
  rm -f "$PID_FILE"
  echo "已强制停止"
}

INSTALL_SYSTEMD="$(get_install_systemd)"

if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
  if have_systemctl && unit_exists; then
    echo "config: install_systemd=true -> 使用 systemctl 停止 ${SERVICE_NAME}"
    systemctl stop "$SERVICE_NAME"
    systemctl status "$SERVICE_NAME" --no-pager || true
    exit 0
  fi
  echo "config: install_systemd=true，但无法使用 systemctl -> 自动降级为 PID 模式停止"
  stop_pid_mode
  exit 0
fi

echo "config: install_systemd=false -> 使用 PID 模式停止"
stop_pid_mode
`, configFileName, defaultServiceName, pidFileName)

	if err := os.WriteFile(startPath, []byte(startContent), 0755); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", startScriptName, err)
	}
	if err := os.WriteFile(stopPath, []byte(stopContent), 0755); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", stopScriptName, err)
	}

	// 再 chmod 一次确保权限
	_ = os.Chmod(startPath, 0755)
	_ = os.Chmod(stopPath, 0755)
	return nil
}

// ---------------- 配置读写 ----------------

func readOrInitConfig(filename string) (Config, string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			def := defaultConfigTemplate()
			if werr := writeConfig(filename, def); werr != nil {
				return Config{}, "", fmt.Errorf("未找到配置文件 %s，尝试创建默认配置失败：%w", filename, werr)
			}
			return def, "initialized", nil
		}
		if os.IsPermission(err) {
			return Config{}, "", fmt.Errorf("读取配置文件 %s 失败：权限不足：%w", filename, err)
		}
		return Config{}, "", fmt.Errorf("读取配置文件 %s 失败：%w", filename, err)
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, "", fmt.Errorf("配置文件 %s 格式错误（不是合法 JSON）：%w", filename, err)
	}
	if cfg.Port == 0 {
		return Config{}, "", fmt.Errorf("配置文件 %s 缺少有效字段：port（示例：{\"port\":30080}）", filename)
	}

	return cfg, "loaded", nil
}

func defaultConfigTemplate() Config {
	return Config{
		Comment: []string{
			"这是极简静态文件服务器的配置文件（合法 JSON，可直接解析）。",
			"port：服务监听端口（范围 1~65535）。默认 30080（避免浏览器对危险端口的拦截）。",
			"install_systemd：是否自动安装为 systemd 常驻服务（true/false）。默认 true。",
			"当 install_systemd=true 时：程序会先尝试停止已存在的 serve-static 服务（避免重复运行/端口冲突），然后写入 unit 并 enable+restart。",
			"程序每次运行都会生成两个脚本（同目录，默认可执行）：",
			fmt.Sprintf("  - %s：读取 config.json 的 install_systemd 决定启动方式（true->systemctl / false->PID nohup）", startScriptName),
			fmt.Sprintf("  - %s：读取 config.json 的 install_systemd 决定停止方式（true->systemctl / false->PID kill）", stopScriptName),
			fmt.Sprintf("PID 模式文件：%s（PID），日志：%s", pidFileName, outLogName),
			"说明：JSON 标准不支持 // 或 /* */ 注释，因此用 _comment 字段承载注释内容。",
			"用法：第一次运行会自动生成本文件并退出；确认无误后再次运行即可启动服务。",
		},
		Port:           defaultPort,
		InstallSystemd: true,
	}
}

func writeConfig(filename string, cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

func validatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("端口不合法：%d（合法范围 1~65535）", p)
	}
	return nil
}

// ---------------- 内置 systemd 安装（方案一） ----------------

func ensureSystemdService(workingDir string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("仅支持在 Linux 上安装 systemd 服务")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("未找到 systemctl，系统可能不是 systemd：%v", err)
	}

	// 按你要求：重复执行先 stop 一下（忽略失败）
	_ = runCmdCN("systemctl", "stop", defaultServiceName)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败：%w", err)
	}
	if realExe, e := filepath.EvalSymlinks(exe); e == nil {
		exe = realExe
	}

	unitPath := filepath.Join("/etc/systemd/system", defaultServiceName+".service")
	unit := renderUnit(defaultServiceName, workingDir, exe)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("写入 %s 失败：权限不足（请用 root 运行或使用 sudo）：%w", unitPath, err)
		}
		return fmt.Errorf("写入 %s 失败：%w", unitPath, err)
	}

	if err := runCmdCN("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCmdCN("systemctl", "enable", defaultServiceName); err != nil {
		return err
	}
	if err := runCmdCN("systemctl", "restart", defaultServiceName); err != nil {
		return err
	}
	return nil
}

func renderUnit(serviceName, wd, exe string) string {
	return fmt.Sprintf(`[Unit]
Description=Go Static Server (%s)
After=network.target

[Service]
Type=simple
WorkingDirectory=%s
Environment=%s=%s
ExecStart=%s
Restart=on-failure
RestartSec=2
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, serviceName, wd, systemdEnvKey, systemdEnvVal, exe)
}

func runCmdCN(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	msg = translateEnglishFragments(msg)
	return fmt.Errorf("执行命令失败：%s %s：%s", name, strings.Join(args, " "), msg)
}

// ---------------- 静态文件服务 ----------------

func newStaticHandler(rootAbs string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "不支持的请求方法：仅支持 GET/HEAD", http.StatusMethodNotAllowed)
			return
		}

		reqPath := r.URL.Path
		if reqPath == "/" {
			reqPath = "/index.html"
		}

		// 仅当路径段 == ".." 才拒绝，避免误伤 /a..b.js
		for _, seg := range strings.Split(reqPath, "/") {
			if seg == ".." {
				http.Error(w, "请求路径不合法：禁止包含 ..", http.StatusBadRequest)
				return
			}
		}

		clean := path.Clean(reqPath)
		rel := strings.TrimPrefix(clean, "/")
		rel = filepath.FromSlash(rel)

		full := filepath.Join(rootAbs, rel)
		abs, err := filepath.Abs(full)
		if err != nil {
			http.Error(w, "服务器内部错误：无法解析文件路径", http.StatusInternalServerError)
			return
		}

		rr, err := filepath.Rel(rootAbs, abs)
		if err != nil {
			http.Error(w, "服务器内部错误：无法校验访问路径", http.StatusInternalServerError)
			return
		}
		if rr == ".." || strings.HasPrefix(rr, ".."+string(os.PathSeparator)) {
			http.Error(w, "禁止访问：越界路径", http.StatusForbidden)
			return
		}

		if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
			abs = filepath.Join(abs, "index.html")
		}

		f, err := os.Open(abs)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil || fi.IsDir() {
			http.NotFound(w, r)
			return
		}

		ext := strings.ToLower(filepath.Ext(fi.Name()))
		if ext != "" {
			if ct := mime.TypeByExtension(ext); ct != "" {
				w.Header().Set("Content-Type", ct)
			}
		}
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		if _, err := io.Copy(w, f); err != nil {
			log.Printf("响应写出失败：%s", cnErrorMessage(err))
			return
		}
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s (%s) %s", ip, r.Method, r.URL.Path, r.UserAgent(), time.Since(start))
	})
}

// ---------------- 统一中文错误输出（尽量不含英文） ----------------

func fatalCN(context string, err error) {
	log.Fatalf("%s：%s", context, cnErrorMessage(err))
}

func cnErrorMessage(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if se, ok := opErr.Err.(*os.SyscallError); ok {
			if msg := cnErrno(se.Err); msg != "" {
				return msg
			}
			return translateEnglishFragments(se.Err.Error())
		}
		if msg := cnErrno(opErr.Err); msg != "" {
			return msg
		}
		return translateEnglishFragments(opErr.Err.Error())
	}

	if errors.Is(err, os.ErrNotExist) {
		return "文件不存在"
	}
	if errors.Is(err, os.ErrPermission) {
		return "权限不足"
	}

	return translateEnglishFragments(err.Error())
}

func cnErrno(inner error) string {
	switch {
	case errors.Is(inner, syscall.EADDRINUSE):
		return "端口已被占用。请更换 config.json 的 port，或停止占用该端口的进程。"
	case errors.Is(inner, syscall.EACCES):
		return "权限不足，无法绑定该端口。若使用 1~1023 端口通常需要管理员权限。"
	case errors.Is(inner, syscall.EADDRNOTAVAIL):
		return "监听地址不可用。请检查监听地址或网络配置。"
	case errors.Is(inner, syscall.ENETUNREACH):
		return "网络不可达。请检查网络设置。"
	default:
		return ""
	}
}

func translateEnglishFragments(s string) string {
	low := strings.ToLower(s)

	type pair struct {
		needle string
		zh     string
	}
	maps := []pair{
		{"address already in use", "端口已被占用"},
		{"permission denied", "权限不足"},
		{"not found", "未找到"},
		{"failed", "失败"},
		{"access denied", "访问被拒绝"},
		{"cannot assign requested address", "无法绑定到请求的地址（地址不可用）"},
		{"address not available", "地址不可用"},
		{"connection refused", "连接被拒绝"},
		{"no such file or directory", "文件或目录不存在"},
		{"i/o timeout", "读写超时"},
		{"network is unreachable", "网络不可达"},
		{"broken pipe", "管道已断开（对端提前关闭连接）"},
		{"system has not been booted with systemd", "系统不是以 systemd 方式启动（可能不支持 systemctl）"},
		{"systemctl: command not found", "未找到 systemctl（系统可能不是 systemd）"},
	}

	for _, m := range maps {
		if strings.Contains(low, m.needle) {
			switch m.needle {
			case "address already in use":
				return m.zh + "。请更换 config.json 的 port，或停止占用该端口的进程。"
			case "permission denied":
				return m.zh + "。请使用 root/sudo 运行，或检查文件/目录权限。"
			case "system has not been booted with systemd":
				return "系统不是以 systemd 方式启动，无法安装/管理 systemd 服务。"
			default:
				return m.zh + "。"
			}
		}
	}
	return s
}
