package main

import "net/http"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		// Semgrep (G103) will find this
		http.ServeFile(w, r, file)
	})
	http.ListenAndServe(":8080", nil)
}
