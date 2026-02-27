# SimpleGoWebServer
一个超简单的go语言实现的web服务，一个文件，直接运行，无任何依赖，考虑各种边界问题。

Linux运行方法：
chmod +x ./serve
./serve



1.在 Windows 上Gitbash里面打 Windows 包（amd64）
mkdir -p dist

export GOOS=windows
export GOARCH=amd64
export CGO_ENABLED=0

go build -ldflags "-s -w" -o dist/serve.exe .
file dist/serve.exe



2.在 Windows 上Gitbash里面打 Linux 包（amd64）

mkdir -p dist

export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

go build -ldflags "-s -w" -o dist/serve .





PowerShell 版本（如果你在 PS 里打）
Linux amd64
mkdir dist -ErrorAction SilentlyContinue
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -ldflags "-s -w" -o dist\serve .
Windows amd64
mkdir dist -ErrorAction SilentlyContinue
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -ldflags "-s -w" -o dist\serve.exe .