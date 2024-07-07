package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"profile", "email"},
		Endpoint:     google.Endpoint,
	}

	githubOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/github/callback",
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
	store = sessions.NewCookieStore([]byte("SESSION_SECRET"))
)

var db *sql.DB
var jwtKey = []byte("your_secret_key") // Keep this key secret

type Thread struct {
	ID          int
	Title       string
	Description string
	Likes       int
	Dislikes    int
}
type Comment struct {
	ID       int
	Content  string
	Username string
	Likes    int
	Dislikes int
	UserID   int
}
type Message struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"` // Ensure field names are correctly capitalized for external visibility
	Recipient string    `json:"recipient"`
	Content   string    `json:"content"`
	Time      time.Time `json:"time"`
}

func handleProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		log.Printf("Error getting session: %v", err) // Log the error
		return
	}

	accessToken, ok := session.Values["accessToken"].(string)
	if !ok {
		http.Error(w, "Access token not found in session", http.StatusInternalServerError)
		log.Println("Access token not found in session") // Log the error
		return
	}

	// Use accessToken to make authenticated requests or perform actions
	fmt.Fprintf(w, "Access Token: %s", accessToken)
}

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	url := githubOauthConfig.AuthCodeURL("state-token")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	log.Printf("GitHub callback code: %s", code) // Log the received code

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange GitHub token", http.StatusInternalServerError)
		log.Printf("GitHub token exchange error: %v", err) // Log the error
		return
	}

	// Store token in session
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Failed to get session", http.StatusInternalServerError)
		log.Printf("Session error: %v", err) // Log the error
		return
	}
	session.Values["githubAccessToken"] = token.AccessToken
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		log.Printf("Session save error: %v", err) // Log the error
		return
	}

	// Redirect to another endpoint after successful login
	http.Redirect(w, r, "/index", http.StatusSeeOther)
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}

// database load
func initDB(dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	// Read and execute SQL commands from schema.sql
	schema, err := ioutil.ReadFile("schema.sql")
	if err != nil {
		return nil, fmt.Errorf("error reading schema.sql: %w", err)
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		return nil, fmt.Errorf("error executing schema.sql: %w", err)
	}

	log.Println("Database initialized successfully.")
	return db, nil
}

func main() {
	jwtKey = generateRandomKey(32)
	log.Println("JWT Key:", base64.StdEncoding.EncodeToString(jwtKey))

	var err error
	db, err = initDB("./forum.db")
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer db.Close()

	http.HandleFunc("/", serveHome)

	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	http.HandleFunc("/auth/github/login", handleGitHubLogin)
	http.HandleFunc("/auth/github/callback", handleGitHubCallback)
	http.HandleFunc("/protected", handleProtectedEndpoint)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/login", serveLogin)
	http.HandleFunc("/register", serveRegister)
	http.HandleFunc("/index", serveIndex)
	http.HandleFunc("/thread", serveThread)
	http.HandleFunc("/logout", serveLogout)
	http.HandleFunc("/login-guest", serveLoginGuest)
	http.HandleFunc("/create-thread", serveCreateThread)
	http.HandleFunc("/like-dislike", handleLikeDislike)
	http.HandleFunc("/comment", serveComment)
	// Set up routes for CHAT
	http.HandleFunc("/messages", serveMessages) // Ensure serveMessages is defined somewhere
	http.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		messageHandler(db)(w, r) // Correctly pass the http.ResponseWriter, *http.Request, and *sql.DB
	}) // API endpoint for handling messages
	// Handler to get current user's username
	http.HandleFunc("/api/get-current-user", func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the session token from the cookie
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Session token not found", http.StatusUnauthorized)
			return
		}
		tokenString := cookie.Value

		// Use the existing function to get user details from the session token
		username, _, err := getUserFromSession(tokenString)
		if err != nil {
			http.Error(w, "Error getting user details: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return the username as JSON
		json.NewEncoder(w).Encode(map[string]string{"username": username})
	})
	//chat ended
	http.HandleFunc("/comment-like-dislike", handleCommentLikeDislike)
	log.Fatal(http.ListenAndServe(":8080", nil))

	//log.Println("JWT Key:", base64.StdEncoding.EncodeToString(jwtKey))
}

// chat only asagidaki
// serveMessages serves the messages.html template
var tmpl = template.Must(template.ParseFiles("templates/messages.html"))

func serveMessages(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Session token not found", http.StatusUnauthorized)
		return
	}
	tokenString := cookie.Value

	// Use the existing function to get user details from the session token
	username, userID, err := getUserFromSession(tokenString)
	if err != nil {
		http.Error(w, "Error getting user details: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare user details for the template
	userDetails := map[string]interface{}{
		"Username": username,
		"UserID":   userID,
	}

	// Execute the template with the user details
	err = tmpl.Execute(w, userDetails)
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// chat done
// CHAT ICIN MESHGUR GET CURRENT USER:
func getCurrentUser(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}

	tokenString := cookie.Value
	username, _, err := getUserFromSession(tokenString)
	if err != nil {
		return "", err
	}

	return username, nil
}

// DONE DONE DONE
// asagida k ve generate Random token olusturmak icin
func generateJWT(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Failed to generate random key:", err)
	}
	return key
}

// guest mi degil mi kontrolu icin asagidaki kullanilabilir
func getUserIDByUsername(username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// guest icin ayri token olusturuyo
func serveLoginGuest(w http.ResponseWriter, r *http.Request) {
	// Generate a guest JWT token
	tokenString, err := generateJWT("guest")
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set the token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   tokenString,
		Expires: time.Now().Add(24 * time.Hour),
		Path:    "/",
	})

	http.Redirect(w, r, "/index", http.StatusSeeOther)
}

// isGuest kontrolu bununla da yapilabilir
// getUserIDByUsername func ile belki birlestirilebilir
func getUserFromSession(tokenString string) (string, int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := claims["username"].(string)
		if username == "guest" {
			return username, 0, nil // Return 0 for userID if guest
		}
		userID, err := getUserIDByUsername(username)
		if err != nil {
			return "", 0, err
		}
		return username, userID, nil
	} else {
		return "", 0, err
	}
}

// /home goruntuleme icin
func serveHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil && cookie.Value != "" {
		// Check if the session token is valid
		username, _, err := getUserFromSession(cookie.Value) // Ignore userID with '_'
		if err == nil && username != "" {
			http.Redirect(w, r, "/index", http.StatusSeeOther)
			return
		}
	}

	// If no valid session, show the home page with login and register options
	tmpl := template.Must(template.ParseFiles("templates/home.html"))
	tmpl.Execute(w, nil)
}

// cookie uzerinden userId elde ediyo
func getUserIDFromCookie(r *http.Request) (int, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return 0, err
	}
	_, userID, err := getUserFromSession(cookie.Value)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// /index goruntuleme
func serveIndex(w http.ResponseWriter, r *http.Request) {
	// Attempt to retrieve the session token and username
	var username string
	cookie, err := r.Cookie("session_token")
	if err == nil {
		username, _, err = getUserFromSession(cookie.Value)
		if err != nil {
			username = "Guest" // Default to "Guest" if session is invalid
		}
	} else {
		username = "Guest" // Treat as "Guest" if no cookie is found
	}

	categoryFilter := r.URL.Query().Get("category")
	likeType := r.URL.Query().Get("likeType") // "like" or "dislike"

	var rows *sql.Rows
	baseQuery := `
        SELECT DISTINCT t.id, t.title, t.description 
        FROM threads t
        LEFT JOIN thread_categories tc ON t.id = tc.thread_id
        LEFT JOIN categories c ON tc.category_id = c.id
    `
	var queryParams []interface{}

	whereClauses := []string{}

	// Filter by category if specified
	if categoryFilter != "" {
		whereClauses = append(whereClauses, "c.name = ?")
		queryParams = append(queryParams, categoryFilter)
	}

	// Filter by like or dislike if specified
	if likeType != "" {
		likeValue := 0
		if likeType == "like" {
			likeValue = 1
		} else if likeType == "dislike" {
			likeValue = -1
		}
		whereClauses = append(whereClauses, "EXISTS (SELECT 1 FROM thread_likes tl WHERE tl.thread_id = t.id AND tl.like_type = ?)")
		queryParams = append(queryParams, likeValue)
	}

	// Construct the final query with all applicable where clauses
	if len(whereClauses) > 0 {
		baseQuery += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Execute the query with all parameters
	rows, err = db.Query(baseQuery, queryParams...)
	if err != nil {
		http.Error(w, "Failed to fetch threads", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var threads []Thread
	for rows.Next() {
		var t Thread
		if err := rows.Scan(&t.ID, &t.Title, &t.Description); err != nil {
			http.Error(w, "Failed to read thread data", http.StatusInternalServerError)
			return
		}
		threads = append(threads, t)
	}

	// Render the page with the filtered threads and username
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Username": username,
		"Threads":  threads,
	})
}

// konu/topic goruntuleme (commentleri ile birlikte)
func serveThread(w http.ResponseWriter, r *http.Request) {
	threadID := r.URL.Query().Get("id")
	if threadID == "" {
		http.Error(w, "Thread ID is required", http.StatusBadRequest)
		return
	}

	var thread Thread
	var username string
	err := db.QueryRow(`
        SELECT t.id, t.title, t.description, t.likes, t.dislikes, u.username 
        FROM threads t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.id = ?`, threadID).Scan(&thread.ID, &thread.Title, &thread.Description, &thread.Likes, &thread.Dislikes, &username)
	if err != nil {
		log.Printf("Failed to fetch thread details: %v", err)
		http.Error(w, "Failed to fetch thread", http.StatusInternalServerError)
		return
	}

	// Fetch categories for the thread
	categoryRows, err := db.Query("SELECT c.name FROM categories c JOIN thread_categories tc ON c.id = tc.category_id WHERE tc.thread_id = ?", threadID)
	if err != nil {
		log.Printf("Failed to fetch categories: %v", err)
		http.Error(w, "Failed to fetch categories", http.StatusInternalServerError)
		return
	}
	defer categoryRows.Close()

	var categories []string
	for categoryRows.Next() {
		var categoryName string
		if err := categoryRows.Scan(&categoryName); err != nil {
			log.Printf("Failed to read category %v", err)
			http.Error(w, "Failed to read category data", http.StatusInternalServerError)
			return
		}
		categories = append(categories, categoryName)
	}

	// Fetch comments for the thread, including likes and dislikes
	rows, err := db.Query("SELECT c.id, c.content, u.username, (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.like_type = 1) AS likes, (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.id AND cl.like_type = -1) AS dislikes FROM comments c JOIN users u ON u.id = c.user_id WHERE c.thread_id = ?", threadID)
	if err != nil {
		log.Printf("Failed to fetch comments: %v", err)
		http.Error(w, "Failed to fetch comments", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.Content, &comment.Username, &comment.Likes, &comment.Dislikes); err != nil {
			log.Printf("Failed to read comment %v", err)
			http.Error(w, "Failed to read comment data", http.StatusInternalServerError)
			return
		}
		comments = append(comments, comment)
	}

	// Render the thread page with all gathered data
	tmpl := template.Must(template.ParseFiles("templates/thread.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Thread":     thread,
		"Username":   username,
		"Categories": categories,
		"Comments":   comments,
	})
}

// /login sistemi
func serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Username not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Database error", http.StatusInternalServerError)
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Generate JWT for the session
		tokenString, err := generateJWT(username)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Set the token in a cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   tokenString,
			Expires: time.Now().Add(24 * time.Hour),
			Path:    "/",
		})

		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	} else {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
	}
}

// logout sistemi
func serveLogout(w http.ResponseWriter, r *http.Request) {
	// Delete the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// register sistemi
// ve hash ile sifreleme
func serveRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error while hashing password", http.StatusInternalServerError)
			return
		}

		_, err = executeQuery("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", username, string(hashedPassword), email)
		if err != nil {
			http.Error(w, "Error while registering user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	} else {
		tmpl := template.Must(template.ParseFiles("templates/register.html"))
		tmpl.Execute(w, nil)
	}
}

// konu like-dislike ve error handling
func handleLikeDislike(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	threadID := r.FormValue("thread_id")
	likeTypeParam := r.FormValue("like_type") // This should be either "1" for like or "-1" for dislike
	likeType, err := strconv.Atoi(likeTypeParam)
	if err != nil || (likeType != 1 && likeType != -1) {
		http.Error(w, "Invalid like type", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromCookie(r)
	if err != nil {
		http.Error(w, "Authentication error", http.StatusUnauthorized)
		return
	}

	username, err := getCurrentUser(r)
	if err != nil {
		// Handle error, maybe log it
		http.Error(w, "Failed to get current user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if username == "guest" {
		// If there's an error or the user is a guest, deny access
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var existingType int
	err = tx.QueryRow("SELECT like_type FROM thread_likes WHERE thread_id = ? AND user_id = ?", threadID, userID).Scan(&existingType)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingType != 0 {
		http.Error(w, "You have already reacted to this thread", http.StatusForbidden)
		return
	}

	_, err = tx.Exec("INSERT INTO thread_likes (thread_id, user_id, like_type) VALUES (?, ?, ?)", threadID, userID, likeType)
	if err != nil {
		http.Error(w, "Failed to record reaction", http.StatusInternalServerError)
		return
	}

	if likeType == 1 {
		_, err = tx.Exec("UPDATE threads SET likes = likes + 1 WHERE id = ?", threadID)
	} else {
		_, err = tx.Exec("UPDATE threads SET dislikes = dislikes + 1 WHERE id = ?", threadID)
	}
	if err != nil {
		http.Error(w, "Failed to update thread", http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/thread?id="+threadID, http.StatusSeeOther)
}

// konu olusturma
func serveCreateThread(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Retrieve the session token from the cookie
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Decode the session token to check if the user is a guest
		username, userID, err := getUserFromSession(cookie.Value)
		if err != nil || username == "guest" {
			// If there's an error or the user is a guest, deny access
			http.Error(w, "Unauthorized access", http.StatusUnauthorized)
			return
		}

		// Proceed with creating the thread since the user is authenticated and not a guest
		title := r.FormValue("title")
		description := r.FormValue("description")
		categories := r.Form["categories"]

		// Insert the new thread
		result, err := db.Exec("INSERT INTO threads (title, description, user_id) VALUES (?, ?, ?)", title, description, userID)
		if err != nil {
			http.Error(w, "Failed to create thread", http.StatusInternalServerError)
			return
		}

		// Get the last inserted thread ID
		threadID, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "Failed to retrieve thread ID", http.StatusInternalServerError)
			return
		}

		// Insert category associations in the thread_categories table
		for _, catID := range categories {
			_, err = db.Exec("INSERT INTO thread_categories (thread_id, category_id) VALUES (?, ?)", threadID, catID)
			if err != nil {
				http.Error(w, "Failed to assign categories", http.StatusInternalServerError)
				return
			}
		}

		// Redirect to the index page after successful creation
		http.Redirect(w, r, "/index", http.StatusSeeOther)
	} else {
		// If the method is not POST, handle it as a bad request
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// yorumlar kismi
func serveComment(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		threadID := r.FormValue("thread_id")
		comment := r.FormValue("comment")
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		username, _, err := getUserFromSession(cookie.Value) // Updated to use getUserFromSession
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		_, err = db.Exec("INSERT INTO comments (content, user_id, thread_id) SELECT ?, id, ? FROM users WHERE username = ?", comment, threadID, username)
		if err != nil {
			http.Error(w, "Failed to post comment", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/thread?id="+threadID, http.StatusSeeOther)
		return
	}
}

// yorum like-dislike
func handleCommentLikeDislike(w http.ResponseWriter, r *http.Request) {

	commentID := r.FormValue("comment_id")
	userID := r.FormValue("user_id")     // Ensure you are capturing the user ID correctly
	likeType := r.FormValue("like_type") // Should be '1' for like or '-1' for dislike

	username, err := getCurrentUser(r)
	if err != nil {
		// Handle error, maybe log it
		http.Error(w, "Failed to get current user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if username == "guest" {
		// If there's an error or the user is a guest, deny access
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}

	// Check if the user has already liked or disliked the comment
	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentID, userID).Scan(&exists)
	if err != nil {
		log.Printf("Error checking existing likes/dislikes: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		// Update existing record
		_, err = db.Exec("UPDATE comment_likes SET like_type = ? WHERE comment_id = ? AND user_id = ?", likeType, commentID, userID)
	} else {
		// Insert new record
		_, err = db.Exec("INSERT INTO comment_likes (comment_id, user_id, like_type) VALUES (?, ?, ?)", commentID, userID, likeType)
	}

	if err != nil {
		log.Printf("Failed to update comment likes/dislikes: %v", err)
		http.Error(w, "Failed to update comment", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/thread?id="+r.FormValue("thread_id"), http.StatusSeeOther)
}

func executeQuery(query string, args ...interface{}) (sql.Result, error) {
	return db.Exec(query, args...)
}

func queryRow(query string, args ...interface{}) *sql.Row {
	return db.QueryRow(query, args...)
}
