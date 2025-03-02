package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const dockerHub = "https://registry-1.docker.io"

var routes map[string]string

func init() {
	customDomain := os.Getenv("CUSTOM_DOMAIN")
	if customDomain == "" {
		log.Fatal("CUSTOM_DOMAIN environment variable is required")
	}

	routes = map[string]string{
		// production
		"docker." + customDomain:     dockerHub,
		"quay." + customDomain:       "https://quay.io",
		"gcr." + customDomain:        "https://gcr.io",
		"k8s-gcr." + customDomain:    "https://k8s.gcr.io",
		"k8s." + customDomain:        "https://registry.k8s.io",
		"ghcr." + customDomain:       "https://ghcr.io",
		"cloudsmith." + customDomain: "https://docker.cloudsmith.io",
		"ecr." + customDomain:        "https://public.ecr.aws",
		// staging
		"docker-staging." + customDomain: dockerHub,
	}
}

type WWWAuthenticate struct {
	Realm   string
	Service string
}

func parseAuthenticate(authenticateStr string) (*WWWAuthenticate, error) {
	parts := strings.Split(authenticateStr, ",")
	auth := &WWWAuthenticate{}

	for _, part := range parts {
		if strings.Contains(part, "realm=") {
			auth.Realm = strings.Trim(strings.Split(part, "realm=")[1], "\"")
		} else if strings.Contains(part, "service=") {
			auth.Service = strings.Trim(strings.Split(part, "service=")[1], "\"")
		}
	}

	if auth.Realm == "" || auth.Service == "" {
		return nil, fmt.Errorf("invalid Www-Authenticate Header: %s", authenticateStr)
	}

	return auth, nil
}

func routeByHosts(host string) string {
	if upstream, ok := routes[host]; ok {
		return upstream
	}
	if os.Getenv("MODE") == "debug" {
		return os.Getenv("TARGET_UPSTREAM")
	}
	return ""
}

func responseUnauthorized(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	host := r.Host
	mode := os.Getenv("MODE")

	if mode == "debug" {
		headers.Set("Www-Authenticate",
			fmt.Sprintf(`Bearer realm="http://%s/v2/auth",service="cloudflare-docker-proxy"`, host))
	} else {
		headers.Set("Www-Authenticate",
			fmt.Sprintf(`Bearer realm="https://%s/v2/auth",service="cloudflare-docker-proxy"`, host))
	}

	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"message": "UNAUTHORIZED"})
}

func main() {
	http.HandleFunc("/", handleRequest)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000" // 默认端口
	}

	log.Printf("代理服务器启动在 :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	upstream := routeByHosts(r.Host)
	if upstream == "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": routes,
		})
		return
	}

	isDockerHub := upstream == dockerHub
	authorization := r.Header.Get("Authorization")

	// 处理 /v2/ 路径
	if r.URL.Path == "/v2/" {
		handleV2Root(w, r, upstream, authorization)
		return
	}

	// 处理认证路径
	if r.URL.Path == "/v2/auth" {
		handleAuth(w, r, upstream, authorization)
		return
	}

	// 处理 DockerHub 库镜像重定向
	if isDockerHub {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) == 5 {
			pathParts = append(pathParts[:2], append([]string{"library"}, pathParts[2:]...)...)
			newURL := fmt.Sprintf("http://%s%s", r.Host, strings.Join(pathParts, "/"))
			http.Redirect(w, r, newURL, http.StatusMovedPermanently)
			return
		}
	}

	// 转发请求
	proxyRequest(w, r, upstream, isDockerHub)
}

func handleV2Root(w http.ResponseWriter, r *http.Request, upstream, authorization string) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", upstream+"/v2/", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		responseUnauthorized(w, r)
		return
	}

	copyResponse(w, resp)
}

func handleAuth(w http.ResponseWriter, r *http.Request, upstream, authorization string) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", upstream+"/v2/", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		copyResponse(w, resp)
		return
	}

	authenticateStr := resp.Header.Get("WWW-Authenticate")
	if authenticateStr == "" {
		copyResponse(w, resp)
		return
	}

	wwwAuthenticate, err := parseAuthenticate(authenticateStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scope := r.URL.Query().Get("scope")
	if scope != "" && upstream == dockerHub {
		scopeParts := strings.Split(scope, ":")
		if len(scopeParts) == 3 && !strings.Contains(scopeParts[1], "/") {
			scopeParts[1] = "library/" + scopeParts[1]
			scope = strings.Join(scopeParts, ":")
		}
	}

	fetchAndForwardToken(w, r, wwwAuthenticate, scope, authorization)
}

func fetchAndForwardToken(w http.ResponseWriter, r *http.Request, auth *WWWAuthenticate, scope, authorization string) {
	tokenURL := auth.Realm
	if auth.Service != "" {
		tokenURL += "?service=" + auth.Service
	}
	if scope != "" {
		if strings.Contains(tokenURL, "?") {
			tokenURL += "&scope=" + scope
		} else {
			tokenURL += "?scope=" + scope
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	copyResponse(w, resp)
}

func proxyRequest(w http.ResponseWriter, r *http.Request, upstream string, isDockerHub bool) {
	client := &http.Client{}
	if isDockerHub {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	newURL := upstream + r.URL.Path
	if r.URL.RawQuery != "" {
		newURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, newURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制原始请求的 headers
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		responseUnauthorized(w, r)
		return
	}

	// 处理 DockerHub blob 重定向
	if isDockerHub && resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		if location != "" {
			redirectResp, err := http.Get(location)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer redirectResp.Body.Close()
			copyResponse(w, redirectResp)
			return
		}
	}

	copyResponse(w, resp)
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	// 复制 headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// 复制 body
	if resp.Body != nil {
		_, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("Error copying response body: %v", err)
		}
	}
}
