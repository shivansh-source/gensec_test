package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ============================================================
// CWE-78: OS Command Injection
// ============================================================

func handlePing(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: User input directly in shell command
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
	// VULNERABLE: User input in shell command
	domain := r.PostFormValue("domain")
	result, _ := exec.Command("bash", "-c", "nslookup "+domain).CombinedOutput()
	w.Write(result)
}

func executeUserCommand(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Direct command execution
	cmd := r.URL.Query().Get("cmd")
	output, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Fprintf(w, "%s", output)
}

// ============================================================
// CWE-89: SQL Injection
// ============================================================

func getUserByID(db *sql.DB, userID string) {
	// VULNERABLE: String concatenation in SQL query
	query := "SELECT * FROM users WHERE id = " + userID
	row := db.QueryRow(query)
	var id, name string
	row.Scan(&id, &name)
}

func searchUsers(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: User input directly in WHERE clause
	searchTerm := r.URL.Query().Get("search")
	query := "SELECT * FROM users WHERE name = '" + searchTerm + "'"
	rows, _ := db.Query(query)
	defer rows.Close()
	
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "Found: %s\n", name)
	}
}

func deleteUser(db *sql.DB, userID string) {
	// VULNERABLE: String concatenation for DELETE
	query := "DELETE FROM users WHERE id = " + userID
	db.Exec(query)
}

func updateUserEmail(db *sql.DB, userID, email string) {
	// VULNERABLE: Multiple concatenations
	query := "UPDATE users SET email = '" + email + "' WHERE id = " + userID
	db.Exec(query)
}

// ============================================================
// CWE-798: Hardcoded Credentials / Secrets
// ============================================================

func getAPIKeys() {
	// VULNERABLE: Hardcoded secrets
	apiKey := "sk_live_51234567890abcdefghijklmnop"
	dbPassword := "super_secret_password_12345"
	privateKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"
	
	fmt.Println(apiKey)
	fmt.Println(dbPassword)
	fmt.Println(privateKey)
}

func getGithubToken() string {
	// VULNERABLE: Hardcoded GitHub token
	return "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
}

func getAWSCredentials() {
	// VULNERABLE: Hardcoded AWS access keys
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	
	fmt.Println("AWS Keys:", accessKey, secretKey)
}

// ============================================================
// CWE-327: Use of Broken or Risky Cryptographic Algorithm
// ============================================================

func hashPasswordMD5(password string) string {
	// VULNERABLE: MD5 is not secure for password hashing
	h := md5.New()
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateWeakHash(data string) string {
	// VULNERABLE: Using MD5 for security-critical operations
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ============================================================
// CWE-79: Cross-Site Scripting (XSS)
// ============================================================

func handleUserComment(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: User input directly in HTML response
	comment := r.URL.Query().Get("comment")
	fmt.Fprintf(w, "<h1>Comment:</h1><p>%s</p>", comment)
}

func displayUserProfile(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No escaping of user input
	username := r.URL.Query().Get("username")
	bio := r.URL.Query().Get("bio")
	
	html := "<html><body>"
	html += "<h1>" + username + "</h1>"
	html += "<p>" + bio + "</p>"
	html += "</body></html>"
	
	fmt.Fprintf(w, html)
}

func renderHTML(w http.ResponseWriter, userContent string) {
	// VULNERABLE: Direct string concatenation in HTML
	response := "<div class='content'>" + userContent + "</div>"
	fmt.Fprintf(w, response)
}

// ============================================================
// CWE-434: Unrestricted File Upload
// ============================================================

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No file type validation
	file, handler, _ := r.FormFile("file")
	defer file.Close()
	
	// VULNERABLE: Using user-provided filename directly
	filepath := "/uploads/" + handler.Filename
	
	// VULNERABLE: Writing file to disk without validation
	data := make([]byte, handler.Size)
	file.Read(data)
	os.WriteFile(filepath, data, 0644)
	
	fmt.Fprintf(w, "File uploaded to: %s\n", filepath)
}

func uploadProfilePicture(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No file size limit
	r.ParseMultipartForm(1000000000) // 1GB - no limit
	
	file, handler, _ := r.FormFile("picture")
	defer file.Close()
	
	// VULNERABLE: Direct filename use
	filename := handler.Filename
	os.WriteFile("/public/uploads/"+filename, nil, 0644)
}

// ============================================================
// CWE-352: Cross-Site Request Forgery (CSRF)
// ============================================================

func transferMoney(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No CSRF token validation
	amount := r.PostFormValue("amount")
	toAccount := r.PostFormValue("to")
	
	// Process transfer without CSRF protection
	fmt.Fprintf(w, "Transferring %s to %s\n", amount, toAccount)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No CSRF token, critical action
	userID := r.PostFormValue("user_id")
	
	// Delete account without CSRF protection
	fmt.Fprintf(w, "Account %s deleted\n", userID)
}

// ============================================================
// CWE-287: Improper Authentication
// ============================================================

func authenticateUser(username, password string) bool {
	// VULNERABLE: Plaintext password comparison
	validUser := "admin"
	validPass := "password123"
	
	return username == validUser && password == validPass
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Weak authentication
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	
	// No rate limiting, no account lockout
	if username == "admin" && password == "admin" {
		fmt.Fprintf(w, "Login successful\n")
		return
	}
	fmt.Fprintf(w, "Login failed\n")
}

// ============================================================
// CWE-494: Download of Code Without Integrity Check
// ============================================================

func downloadAndExecute(url string) {
	// VULNERABLE: Downloading code without verification
	cmd := exec.Command("curl", "-O", url)
	cmd.Run()
	
	// VULNERABLE: Executing downloaded file
	exec.Command("bash", "-c", "chmod +x downloaded_file && ./downloaded_file").Run()
}

// ============================================================
// CWE-295: Improper Certificate Validation
// ============================================================

func unsecureHTTPRequest(url string) {
	// VULNERABLE: No certificate validation (if using TLS)
	// This would need to be in actual TLS code, but showing the vulnerability
	http.Get(url) // No validation
}

// ============================================================
// CWE-476: NULL Pointer Dereference
// ============================================================

func processUserData(user interface{}) {
	// VULNERABLE: No null check before accessing
	userData := user.(map[string]interface{})
	name := userData["name"].(string) // Could panic if nil
	fmt.Println(name)
}

// ============================================================
// CWE-190: Integer Overflow
// ============================================================

func calculatePrice(quantity int, unitPrice int) int {
	// VULNERABLE: Integer overflow possible
	totalPrice := quantity * unitPrice // No overflow check
	return totalPrice
}

// ============================================================
// CWE-400: Uncontrolled Resource Consumption
// ============================================================

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No request size limit
	data, _ := os.ReadFile(r.URL.Query().Get("file"))
	w.Write(data)
}

func infiniteLoop(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: User input controls loop
	count := r.URL.Query().Get("count")
	num, _ := strconv.Atoi(count)
	
	for i := 0; i < num; i++ { // No limit - DoS
		fmt.Fprintf(w, "Iteration %d\n", i)
	}
}

// ============================================================
// CWE-798: Hardcoded Connection String
// ============================================================

func getDatabaseConnection() {
	// VULNERABLE: Hardcoded DB credentials in connection string
	connStr := "user=admin password=MySuperSecretPassword123 host=db.example.com port=5432 sslmode=disable"
	fmt.Println(connStr)
}

// ============================================================
// CWE-89: Path Traversal via File Path
// ============================================================

func readFile(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: User input directly in filepath
	filename := r.URL.Query().Get("file")
	data, _ := os.ReadFile("/var/www/files/" + filename)
	w.Write(data)
}

func serveUserFile(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Path traversal - can access ../../../etc/passwd
	filepath := "/uploads/" + r.URL.Query().Get("path")
	data, _ := os.ReadFile(filepath)
	fmt.Fprintf(w, "%s", string(data))
}

// ============================================================
// Main function with HTTP server
// ============================================================

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
	fmt.Println("⚠️  WARNING: This server has intentional vulnerabilities for testing only!")
	
	http.ListenAndServe(":8080", nil)
}
