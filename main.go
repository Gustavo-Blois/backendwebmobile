package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"encoding/base64"
)

const bcryptCost = 12

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
    return string(bytes), err
}

func Login(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
            return
        }

        if err := r.ParseForm(); err != nil {
            http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
            return
        }
        user := r.FormValue("user")
        pass := r.FormValue("password")
        if user == "" || pass == "" {
            http.Error(w, "Usuário e senha são obrigatórios", http.StatusBadRequest)
            return
        }

        var storedHash string
        if err := db.QueryRow(`SELECT password FROM users WHERE name = ?`, user).Scan(&storedHash); err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
                return
            }
            log.Printf("db error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }
        if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(pass)); err != nil {
            http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
            return
        }

        raw := user + "|" + storedHash
        token := base64.StdEncoding.EncodeToString([]byte(raw))

        http.SetCookie(w, &http.Cookie{
            Name:     "fintrack_session",
            Value:    token,
            Path:     "/",                     // enviado em todas as rotas
            MaxAge:   3600,                    // 1 h
            HttpOnly: true,                    // JavaScript não acessa
            Secure:   true,                    // só via HTTPS em prod
            SameSite: http.SameSiteStrictMode, // CSRF
        })

        w.Header().Set("Content-Type", "application/json")
        fmt.Fprintf(w, `{"session":"%s"}`, token)
    }
}

// CreateUser registra um novo usuário com verificação básica.
func CreateUser(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
            return
        }

        if err := r.ParseForm(); err != nil {
            http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
            return
        }
        user := r.FormValue("user")
        pass := r.FormValue("password")
        if user == "" || pass == "" {
            http.Error(w, "Usuário e senha são obrigatórios", http.StatusBadRequest)
            return
        }

        // Checar se já existe
        var exists int
        if err := db.QueryRow(`SELECT 1 FROM users WHERE name = ?`, user).Scan(&exists); err == nil {
            http.Error(w, "Usuário já existe", http.StatusConflict)
            return
        }

        hash, err := HashPassword(pass)
        if err != nil {
            log.Printf("hash error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }

        if _, err := db.Exec(`INSERT INTO users(name, password) VALUES (?, ?)`, user, hash); err != nil {
            log.Printf("insert error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusCreated)
        fmt.Fprintln(w, "Usuário criado com sucesso")
    }
}


func admin(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w,"Bem vindo à area do admin");
}

func InitDB() *sql.DB{
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS users (
        name TEXT NOT NULL PRIMARY KEY,
        password TEXT NOT NULL
    );
    `

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'users' created successfully")
	return db
}

func main() {
	
	db := InitDB()
	defer db.Close()
	r := mux.NewRouter()

	r.HandleFunc("/login",Login(db)).Methods("POST")
	r.HandleFunc("/cria_user",CreateUser(db)).Methods("POST")
	r.HandleFunc("/admin",admin).Methods("GET")
	http.ListenAndServe(":8080",r)
	log.Println("Servidor em 127.0.0.1:8080")
}
