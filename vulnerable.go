package main

import (
	"crypto/md5" // weak hash
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	_ "github.com/lib/pq"
)

// 🔐 Hardcoded secret (for Gitleaks)
const hardcodedAPIKey = "AKIAFAKESECRETKEY123456"

// Insecure global DB (no TLS, no context, bad DSN)
func connectDB() *sql.DB {
	// DSN with hardcoded password and no SSL
	dsn := "postgres://user:password@localhost:5432/appdb?sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// Command injection: user input directly into shell
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host") // SOURCE: untrusted input

	// ❌ SINK: command injection (no validation)
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, _ := cmd.CombinedOutput()

	fmt.Fprintf(w, "Ping result:\n%s", string(out))
}

// SQL injection: string concatenation
func userHandler(w http.ResponseWriter, r *http.Request) {
	db := connectDB()
	defer db.Close()

	username := r.URL.Query().Get("user") // SOURCE

	// ❌ SQL injection with string concatenation
	query := "SELECT id, email FROM users WHERE username = '" + username + "'"
	row := db.QueryRow(query)

	var id int
	var email string
	if err := row.Scan(&id, &email); err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}

	fmt.Fprintf(w, "User: %d, %s", id, email)
}

// Weak crypto + hardcoded secret
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		user = "guest"
	}

	// ❌ Weak hash (MD5) + hardcoded secret
	h := md5.Sum([]byte(user + ":" + hardcodedAPIKey + ":" + time.Now().Format(time.RFC3339)))
	token := hex.EncodeToString(h[:])

	fmt.Fprintf(w, "Your insecure token: %s", token)
}

// Leaky debug handler
func debugHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ENV:\n")
	for _, e := range os.Environ() {
		fmt.Fprintln(w, e) // ❌ Potential secret leak
	}
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/debug", debugHandler)

	// ❌ No TLS (Semgrep rule: use-tls)
	log.Println("Starting HTTP server on :8080 (insecure)...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
