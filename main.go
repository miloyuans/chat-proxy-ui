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
	store        = sessions.NewCookieStore([]byte("secret-key")) // 会话存储
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
	// 创建默认超管（用户名: admin, 密码: admin123，实际生产改）
	hash := sha256.Sum256([]byte("admin123"))
	_, _ = db.Exec("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", "admin", hex.EncodeToString(hash[:]), "admin")
}

// 哈希密码
func hashPassword(pass string) string {
	hash := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(hash[:])
}

// 获取当前用户
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

// 中间件：检查登录
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

// 中间件：检查超管
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

// 模拟登录 ChatGPT Pro（每个用户独立）
// loginToChatGPT 优化版：支持手动 cookie 注入或自动化登录
func loginToChatGPT(username, password, cookieJSON string) (string, error) {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()

    var sessionToken string

    // 模式1: 手动 cookie 注入（推荐，避开 CAPTCHA）
    if cookieJSON != "" {
        // 解析 cookie JSON（假设用户上传 JSON 字符串，格式如 EditThisCookie 导出）
        var cookies []*network.Cookie
        // 这里添加 JSON 解析逻辑（使用 json.Unmarshal 解析 cookieJSON 到 cookies 切片）
        // 示例假设已解析
        err := chromedp.Run(ctx,
            chromedp.Navigate("https://chat.openai.com"),
            chromedp.ActionFunc(func(ctx context.Context) error {
                return network.SetCookies(cookies).Do(ctx)
            }),
            chromedp.Sleep(3 * time.Second),
            chromedp.ActionFunc(func(ctx context.Context) error {
                // 检查是否登录成功（等待 chat 元素出现）
                return chromedp.WaitVisible(`div[data-testid="conversation-panel"]`, chromedp.ByQuery).Do(ctx)
            }),
            // 提取 token
            chromedp.ActionFunc(func(ctx context.Context) error {
                allCookies, err := network.GetCookies().WithURLs([]string{"https://chat.openai.com"}).Do(ctx)
                if err != nil {
                    return err
                }
                for _, cookie := range allCookies {
                    if strings.Contains(cookie.Name, "session-token") || strings.Contains(cookie.Name, "next-auth.session-token") {
                        sessionToken = cookie.Value
                        return nil
                    }
                }
                return fmt.Errorf("session token not found after cookie injection")
            }),
        )
        if err != nil {
            return "", err
        }
        return sessionToken, nil
    }

    // 模式2: 自动化登录（优化 selector 和等待，备用）
    err := chromedp.Run(ctx,
        chromedp.Navigate("https://chat.openai.com/auth/login"),
        chromedp.WaitVisible(`input[type="email"]`, chromedp.ByQuery),  // 优化：等待元素可见

        chromedp.SendKeys(`input[type="email"]`, username, chromedp.ByQuery),
        chromedp.Click(`button[data-testid="continue-button"]`, chromedp.ByQuery),  // 优化 selector
        chromedp.WaitVisible(`input[type="password"]`, chromedp.ByQuery),

        chromedp.SendKeys(`input[type="password"]`, password, chromedp.ByQuery),
        chromedp.Click(`button[data-testid="login-button"]`, chromedp.ByQuery),
        chromedp.Sleep(10 * time.Second),  // 延长等待，处理重定向/验证码

        chromedp.ActionFunc(func(ctx context.Context) error {
            // 检查登录成功
            currentURL := ""
            chromedp.Location(&currentURL).Do(ctx)
            if !strings.Contains(currentURL, "/chat") {
                return fmt.Errorf("login redirect failed, possible CAPTCHA")
            }
            return nil
        }),
        chromedp.ActionFunc(func(ctx context.Context) error {
            cookies, err := network.GetCookies().WithURLs([]string{"https://chat.openai.com"}).Do(ctx)
            if err != nil {
                return err
            }
            for _, cookie := range cookies {
                if strings.Contains(cookie.Name, "session-token") || strings.Contains(cookie.Name, "next-auth.session-token") {
                    sessionToken = cookie.Value
                    return nil
                }
            }
            return fmt.Errorf("session token not found")
        }),
    )
    if err != nil {
        return "", err
    }
    return sessionToken, nil
}

// 获取用户 session token（隔离存储）
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

	// 注册（仅超管允许，或关闭）
	r.POST("/register", adminMiddleware(), func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		role := "user" // 默认普通用户
		hash := hashPassword(password)
		_, err := db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, hash, role)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Registration failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User registered"})
	})

	// 授权 Pro 账号（每个用户独立授权）
	r.POST("/authorize", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		proUsername := c.PostForm("pro_username")
		proPassword := c.PostForm("pro_password")
		cookieJSON := c.PostForm("cookie_json")  // 新字段，用户输入 cookie JSON 字符串

		token, err := loginToChatGPT(proUsername, proPassword, cookieJSON)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: " + err.Error()})
			return
		}
		setUserSessionToken(user.ID, token)
		c.JSON(http.StatusOK, gin.H{"message": "Authorized successfully"})
	})

	// 主页（聊天 UI）
	r.GET("/", authMiddleware(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 聊天代理（使用用户自己的 session token，历史隔离）
	r.POST("/chat", authMiddleware(), func(c *gin.Context) {
		user := getCurrentUser(c)
		var reqBody struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&reqBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 保存用户消息到隔离历史
		_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)", user.ID, "user", reqBody.Message)

		token := getUserSessionToken(user.ID)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No session token, authorize first"})
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

		// 流式响应，并保存助理消息
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
			// 保存到历史
			_, _ = db.Exec("INSERT INTO chat_history (user_id, role, content) VALUES (?, ?, ?)", user.ID, "assistant", assistantMsg)
			return false
		})
	})

	// 获取聊天历史（隔离：只返回当前用户的历史）
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
			history = append(history, map[string]string{"role": role, "content": content, "timestamp": timestamp})
		}
		c.JSON(http.StatusOK, history)
	})

	// 管理界面（仅超管）：列出用户等
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