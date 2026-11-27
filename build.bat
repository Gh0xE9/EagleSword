@echo off
REM EagleSword Windows 构建脚本

setlocal enabledelayedexpansion

set PROJECT_NAME=eaglesword
set BUILD_DIR=dist
set MAIN_FILE=main.go
set VERSION=EG-0.0.1

echo === EagleSword Windows 构建脚本 ===
echo 版本: %VERSION%
echo.

REM 清理旧的构建文件
if exist %BUILD_DIR%\windows rmdir /s /q %BUILD_DIR%\windows
mkdir %BUILD_DIR%\windows

echo 构建 Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o %BUILD_DIR%\windows\%PROJECT_NAME%-windows-amd64.exe %MAIN_FILE%
if errorlevel 1 (
    echo 构建失败！
    exit /b 1
)
echo ✓ Windows (amd64) 构建完成

echo 构建 Windows (arm64)...
set GOOS=windows
set GOARCH=arm64
go build -ldflags="-s -w" -o %BUILD_DIR%\windows\%PROJECT_NAME%-windows-arm64.exe %MAIN_FILE%
if errorlevel 1 (
    echo 构建失败！
    exit /b 1
)
echo ✓ Windows (arm64) 构建完成

echo.
echo === 构建完成 ===
echo 构建目录: %BUILD_DIR%\windows\
dir %BUILD_DIR%\windows\

