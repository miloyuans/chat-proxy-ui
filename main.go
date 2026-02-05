package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// 全局变量
var (
	db           *sql.DB
	store        = sessions.NewCookieStore([]byte("secret-key-change-this"))
	sessionMutex sync.Mutex
)

// 用户结构体
type User struct {
	ID       int
	Username string
	Password string
	Role     string
}

// 初始化数据库
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password TEXT,
			role TEXT
		);
		CREATE TABLE IF NOT EXISTS chat_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			role TEXT,
			content TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS user_sessions (
			user_id INTEGER PRIMARY KEY,
			session_token TEXT
		);
	`)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256([]byte("admin123"))
	_, _ = db.Exec("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", "admin", hex.EncodeToString(hash[:]), "admin")
}

func hashPassword(pass string) string {
	h := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(h[:])
}

func getCurrentUser(c *gin.Context) *User {
	session, _ := store.Get(c.Request, "session")
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return nil
	}
	var user User
	err := db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		return nil
	}
	return &user
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if getCurrentUser(c) == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := getCurrentUser(c)
		if user == nil || user.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// 登录页
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	// 登录处理
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var user User
		err := db.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Password, &user.Role)
		if err != nil || user.Password != hashPassword(password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}

		session, _ := store.Get(c.Request, "session")
		session.Values["user_id"] = user.ID
		session.Save(c.Request, c.Writer)

		c.Redirect(http.StatusFound, "/")
	})

	// 注册（仅管理员）
	r.POST("/register", adminMiddleware(), func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		hash := hashPassword(password)
		_, err := db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", username, hash)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "注册失败，可能用户名已存在"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "注册成功"})
	})

	// 授权页面（手动粘贴 token）
	r.POST("/authorize", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		token := c.PostForm("session_token")

		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请粘贴 session token"})
			return
		}

		// 简单验证 token 格式（可选）
		if len(token) < 20 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token 格式不正确"})
			return
		}

		setUserSessionToken(user.ID, token)
		c.JSON(http.StatusOK, gin.H{"message": "授权成功"})
	})

	// 主页
	r.GET("/", authMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 聊天
	r.POST("/chat", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		var req struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "无效请求"})
			return
		}

		_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, 'user', ?)", user.ID, req.Message)

		token := getUserSessionToken(user.ID)
		if token == "" {
			c.JSON(401, gin.H{"error": "未授权，请先完成授权"})
			return
		}

		body := []byte(fmt.Sprintf(`{"action":"next","messages":[{"role":"user","content":{"content_type":"text","parts":["%s"]}}],"model":"gpt-4o"}`, req.Message))
		reqHTTP, _ := http.NewRequest("POST", "https://chat.openai.com/backend-api/conversation", bytes.NewBuffer(body))
		reqHTTP.Header.Set("Authorization", "Bearer "+token)
		reqHTTP.Header.Set("Content-Type", "application/json")
		reqHTTP.Header.Set("User-Agent", "Mozilla/5.0 ...")

		client := &http.Client{}
		resp, err := client.Do(reqHTTP)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer resp.Body.Close()

		var assistantMsg string
		c.Stream(func(w io.Writer) bool {
			buf := make([]byte, 512)
			n, err := resp.Body.Read(buf)
			if n > 0 {
				assistantMsg += string(buf[:n])
				w.Write(buf[:n])
			}
			if err == nil {
				return true
			}
			_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, 'assistant', ?)", user.ID, assistantMsg)
			return false
		})
	})

	// 历史记录
	r.GET("/history", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		rows, _ := db.Query("SELECT role, content, timestamp FROM chat_history WHERE user_id = ? ORDER BY timestamp", user.ID)
		defer rows.Close()

		var history []map[string]string
		for rows.Next() {
			var role, content, ts string
			rows.Scan(&role, &content, &ts)
			history = append(history, map[string]string{"role": role, "content": content, "timestamp": ts})
		}
		c.JSON(http.StatusOK, history)
	})

	// 管理员用户列表
	r.GET("/admin/users", adminMiddleware(), func(c *gin.Context) {
		rows, _ := db.Query("SELECT id, username, role FROM users")
		defer rows.Close()
		var users []map[string]interface{}
		for rows.Next() {
			var id int
			var username, role string
			rows.Scan(&id, &username, &role)
			users = append(users, map[string]interface{}{"id": id, "username": username, "role": role})
		}
		c.JSON(http.StatusOK, users)
	})

	r.Run(":8080")
}

// 辅助函数
func setUserSessionToken(userID int, token string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	db.Exec("INSERT OR REPLACE INTO user_sessions (user_id, session_token) VALUES (?, ?)", userID, token)
}

func getUserSessionToken(userID int) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	var token string
	db.QueryRow("SELECT session_token FROM user_sessions WHERE user_id = ?", userID).Scan(&token)
	return token
}