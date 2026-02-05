package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// 全局变量
var (
	db           *sql.DB
	store        = sessions.NewCookieStore([]byte("secret-key")) // 会话存储密钥，生产环境请改成安全的随机值
	sessionMutex sync.Mutex                              // 会话锁
)

// 用户结构体
type User struct {
	ID       int
	Username string
	Password string // 哈希存储
	Role     string // "admin" 或 "user"
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
	// 创建默认超管（用户名: admin, 密码: admin123，生产环境请修改）
	hash := sha256.Sum256([]byte("admin123"))
	_, _ = db.Exec("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", "admin", hex.EncodeToString(hash[:]), "admin")
}

// 哈希密码
func hashPassword(pass string) string {
	hash := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(hash[:])
}

// 获取当前登录用户
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

// 中间件：必须登录
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

// 中间件：仅超管
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

// 使用手动导出的 Cookie JSON 进行授权（最稳定方式）
func authorizeWithCookieJSON(cookieJSON string) (string, error) {
	if cookieJSON == "" {
		return "", fmt.Errorf("cookie_json is required")
	}

	var cookieParams []*network.CookieParam
	if err := json.Unmarshal([]byte(cookieJSON), &cookieParams); err != nil {
		return "", fmt.Errorf("invalid cookie json format: %w", err)
	}

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var sessionToken string

	err := chromedp.Run(ctx,
		chromedp.Navigate("https://chat.openai.com"),
		network.SetCookies(cookieParams),
		chromedp.Sleep(3*time.Second),

		// 验证是否登录成功（等待聊天界面元素出现）
		chromedp.WaitVisible(`div[data-testid="conversation-panel"]`, chromedp.ByQuery),

		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().WithURLs([]string{"https://chat.openai.com"}).Do(ctx)
			if err != nil {
				return err
			}
			for _, cookie := range cookies {
				if strings.Contains(cookie.Name, "session-token") ||
					strings.Contains(cookie.Name, "next-auth.session-token") {
					sessionToken = cookie.Value
					return nil
				}
			}
			return fmt.Errorf("session token not found after setting cookies")
		}),
	)

	if err != nil {
		return "", fmt.Errorf("failed to set cookies or verify login: %w", err)
	}

	return sessionToken, nil
}

// 获取用户 session token
func getUserSessionToken(userID int) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	var token string
	db.QueryRow("SELECT session_token FROM user_sessions WHERE user_id = ?", userID).Scan(&token)
	return token
}

// 设置用户 session token
func setUserSessionToken(userID int, token string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	_, _ = db.Exec("INSERT OR REPLACE INTO user_sessions (user_id, session_token) VALUES (?, ?)", userID, token)
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// 登录页面
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		session, _ := store.Get(c.Request, "session")
		session.Values["user_id"] = user.ID
		session.Save(c.Request, c.Writer)
		c.Redirect(http.StatusFound, "/")
	})

	// 注册（仅超管）
	r.POST("/register", adminMiddleware(), func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		role := "user"
		hash := hashPassword(password)
		_, err := db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, hash, role)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Registration failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User registered"})
	})

	// 授权 ChatGPT Pro（手动 Cookie JSON 注入）
	r.POST("/authorize", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		cookieJSON := c.PostForm("cookie_json")

		token, err := authorizeWithCookieJSON(cookieJSON)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: " + err.Error()})
			return
		}

		setUserSessionToken(user.ID, token)
		c.JSON(http.StatusOK, gin.H{"message": "Authorized successfully"})
	})

	// 主页（聊天界面）
	r.GET("/", authMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 聊天代理
	r.POST("/chat", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		var reqBody struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&reqBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 保存用户消息
		_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)", user.ID, "user", reqBody.Message)

		token := getUserSessionToken(user.ID)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No session token, please authorize first"})
			return
		}

		body := []byte(fmt.Sprintf(`{"action":"next","messages":[{"id":"msg-id","role":"user","content":{"content_type":"text","parts":["%s"]}}],"parent_message_id":"parent-id","model":"gpt-4o"}`, reqBody.Message))
		req, _ := http.NewRequest("POST", "https://chat.openai.com/backend-api/conversation", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)", user.ID, "assistant", assistantMsg)
			return false
		})
	})

	// 获取当前用户聊天历史
	r.GET("/history", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		rows, err := db.Query("SELECT role, content, timestamp FROM chat_history WHERE user_id = ? ORDER BY timestamp", user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var history []map[string]string
		for rows.Next() {
			var role, content, timestamp string
			rows.Scan(&role, &content, &timestamp)
			history = append(history, map[string]string{
				"role":      role,
				"content":   content,
				"timestamp": timestamp,
			})
		}
		c.JSON(http.StatusOK, history)
	})

	// 管理用户（仅超管）
	r.GET("/admin/users", adminMiddleware(), func(c *gin.Context) {
		rows, err := db.Query("SELECT id, username, role FROM users")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			rows.Scan(&user.ID, &user.Username, &user.Role)
			users = append(users, user)
		}
		c.JSON(http.StatusOK, users)
	})

	r.Run(":8080")
}