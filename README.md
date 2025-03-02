# Docker Registry Proxy

一个用 Go 编写的 Docker 镜像仓库代理服务，支持多个镜像源的统一代理访问。

## 功能特性

- 支持多个镜像源代理：
  - Docker Hub (`docker.example.com`)
  - Quay.io (`quay.example.com`)
  - Google Container Registry (`gcr.example.com`)
  - GitHub Container Registry (`ghcr.example.com`)
  - AWS ECR Public (`ecr.example.com`)
  - 等更多镜像源...
- 自动处理认证流程
- 支持 Docker Hub 官方镜像重定向
- 支持调试模式

## 快速开始

### 使用 Docker Compose

1. 创建 `docker-compose.yml` 文件：
