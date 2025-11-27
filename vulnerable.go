package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(w, "Ping result:\n%s\n", string(out))
}

func handleDNSLookup(w http.ResponseWriter, r *http.Request) {
	domain := r.PostFormValue("domain")
	result, _ := exec.Command("bash", "-c", "nslookup "+domain).CombinedOutput()
	w.Write(result)
}

func executeUserCommand(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	output, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Fprintf(w, "%s", output)
}

func getUserByID(db *sql.DB, userID string) {
	query := "SELECT * FROM users WHERE id = $1"
	row := db.QueryRow(query, userID)
	var id, name string
	row.Scan(&id, &name)
}

func searchUsers(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("search")
	query := "SELECT * FROM users WHERE name = $1"
	rows, _ := db.Query(query, searchTerm)
	defer rows.Close()

	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "Found: %s\n", name)
	}
}

func deleteUser(db *sql.DB, userID string) {
	query := "DELETE FROM users WHERE id = $1"
	db.Exec(query, userID)
}

func updateUserEmail(db *sql.DB, userID, email string) {
	query := "UPDATE users SET email = $1 WHERE id = $2"
	db.Exec(query, email, userID)
}

func getAPIKeys() {
	apiKey := os.Getenv("API_KEY")
	dbPassword := os.Getenv("DB_PASSWORD")
	privateKey := os.Getenv("PRIVATE_KEY")

	fmt.Println(apiKey)
	fmt.Println(dbPassword)
	fmt.Println(privateKey)
}

func getGithubToken() string {
	return os.Getenv("GITHUB_TOKEN")
}

func getAWSCredentials() {
	accessKey := os.Getenv("AWS_ACCESS_KEY")
	secretKey := os.Getenv("AWS_SECRET_KEY")

	fmt.Println("AWS Keys:", accessKey, secretKey)
}

func hashPasswordMD5(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateWeakHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func handleUserComment(w http.ResponseWriter, r *http.Request) {
	comment := r.URL.Query().Get("comment")
	fmt.Fprintf(w, "<h1>Comment:</h1><p>%s</p>", comment)
}

func displayUserProfile(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	bio := r.URL.Query().Get("bio")

	html := "<html><body>"
	html += "<h1>" + username + "</h1>"
	html += "<p>" + bio + "</p>"
	html += "</body></html)"

	fmt.Fprintf(w, html)
}

func renderHTML(w http.ResponseWriter, userContent string) {
	response := "<div class='content'>" + userContent + "</div>"
	fmt.Fprintf(w, response)
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	file, handler, _ := r.FormFile("file")
	defer file.Close()

	filepath := "/uploads/" + handler.Filename

	data := make([]byte, handler.Size)
	file.Read(data)
	os.WriteFile(filepath, data, 0644)

	fmt.Fprintf(w, "File uploaded to: %s\n", filepath)
}

func uploadProfilePicture(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(1000000000) // 1GB - no limit

	file, handler, _ := r.FormFile("picture")
	defer file.Close()

	filename := handler.Filename
	os.WriteFile("/public/uploads/"+filename, nil, 0644)
}

func transferMoney(w http.ResponseWriter, r *http.Request) {
	amount := r.PostFormValue("amount")
	toAccount := r.PostFormValue("to")

	// Process transfer without CSRF protection
	fmt.Fprintf(w, "Transferring %s to %s\n", amount, toAccount)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	userID := r.PostFormValue("user_id")

	// Delete account without CSRF protection
	fmt.Fprintf(w, "Account %s deleted\n", userID)
}

func authenticateUser(username, password string) bool {
	validUser := "admin"
	validPass := "password123"

	return username == validUser && password == validPass
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	// No rate limiting, no account lockout
	if username == "admin" && password == "admin" {
		fmt.Fprintf(w, "Login successful\n")
		return
	}
	fmt.Fprintf(w, "Login failed\n")
}

func downloadAndExecute(url string) {
	cmd := exec.Command("curl", "-O", url)
	cmd.Run()

	// VULNERABLE: Executing downloaded file
	exec.Command("bash", "-c", "chmod +x downloaded_file && ./downloaded_file").Run()
}

func unsecureHTTPRequest(url string) {
	http.Get(url) // No validation
}

func processUserData(user interface{}) {
	userData := user.(map[string]interface{})
	name := userData["name"].(string) // Could panic if nil
	fmt.Println(name)
}

func calculatePrice(quantity int, unitPrice int) int {
	totalPrice := quantity * unitPrice // No overflow check
	return totalPrice
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(r.URL.Query().Get("file"))
	w.Write(data)
}

func infiniteLoop(w http.ResponseWriter, r *http.Request) {
	count := r.URL.Query().Get("count")
	num, _ := strconv.Atoi(count)

	for i := 0; i < num; i++ { // No limit - DoS
		fmt.Fprintf(w, "Iteration %d\n", i)
	}
}

func getDatabaseConnection() {
	connStr := os.Getenv("DATABASE_CONNECTION")
	fmt.Println(connStr)
}

func readFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, _ := os.ReadFile("/var/www/files/" + filename)
	w.Write(data)
}

func serveUserFile(w http.ResponseWriter, r *http.Request) {
	filepath := "/uploads/" + r.URL.Query().Get("path")
	data, _ := os.ReadFile(filepath)
	fmt.Fprintf(w, "%s", string(data))
}

func main() {
	http.HandleFunc("/ping", handlePing)
	http.HandleFunc("/dns", handleDNSLookup)
	http.HandleFunc("/cmd", executeUserCommand)
	http.HandleFunc("/comment", handleUserComment)
	http.HandleFunc("/upload", handleFileUpload)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/transfer", transferMoney)
	http.HandleFunc("/file", readFile)

	fmt.Println("Vulnerable Go Server started on :8080")
	fmt.Println("WARNING: This server has intentional vulnerabilities for testing only!")

	http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
}