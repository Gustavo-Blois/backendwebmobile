package main

import (
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/gorilla/mux"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// -----------------------------------------------------------------------------
// utilitários
// -----------------------------------------------------------------------------

func HashPassword(password string) (string, error) {
    b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
    return string(b), err
}

// valida user | hash vindo do cookie
func userMatches(db *sql.DB, user, hash string) bool {
    var stored string
    if err := db.QueryRow(`SELECT password FROM users WHERE name = ?`, user).Scan(&stored); err != nil {
        return false
    }
    return stored == hash // hash já veio do banco no login; comparação direta é suficiente
}

func UserMatchesPassword(db *sql.DB, user string, pass string) bool{

    var storedHash string
    if err := db.QueryRow(`SELECT password FROM users WHERE name = ?`, user).Scan(&storedHash); err != nil {
            if err == sql.ErrNoRows {
                return false
            }
            log.Printf("db error: %v", err)
            return false
    }
    if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(pass)); err != nil {
            return false
    }
    return true
}

// decodifica o cookie e devolve user e hash
func parseSessionCookie(r *http.Request) (user, hash string, ok bool) {
    c, err := r.Cookie("fintrack_session")
    if err != nil {
        return
    }
    raw, err := base64.StdEncoding.DecodeString(c.Value)
    if err != nil {
        return
    }
    parts := strings.SplitN(string(raw), "|", 2)
    if len(parts) != 2 {
        return
    }
    return parts[0], parts[1], true
}

// -----------------------------------------------------------------------------
// handlers
// -----------------------------------------------------------------------------

// Retorna as 10 transações mais recentes do usuário autenticado.
func RetTransactions(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        rows, err := db.Query(`
            SELECT id, value, status, date 
            FROM transactions 
            WHERE user = ? 
            ORDER BY date DESC 
            LIMIT 10`, user)
        if err != nil {
            log.Printf("query error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        type Tx struct {
            ID     int    `json:"id"`
            Value  int    `json:"value"`
            Status string `json:"status"`
            Date   int64  `json:"date"`
        }
        var txs []Tx
        for rows.Next() {
            var t Tx
            if err := rows.Scan(&t.ID, &t.Value, &t.Status, &t.Date); err != nil {
                log.Printf("scan error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            txs = append(txs, t)
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(txs)
    }
}

// Insere uma transação para o usuário autenticado.
// Espera form fields: value (int), status ("in" | "out"), date (opcional, epoch segundos).
func PostTransactions(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
            return
        }
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
            return
        }

        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        valStr := r.FormValue("value")
        status := r.FormValue("status")
        if valStr == "" || (status != "in" && status != "out") {
            http.Error(w, "Campos obrigatórios: value, status ('in' ou 'out')", http.StatusBadRequest)
            return
        }

        value, err := strconv.Atoi(valStr)
        if err != nil {
            http.Error(w, "value deve ser inteiro", http.StatusBadRequest)
            return
        }

        // se o campo date não vier, usa agora
        dateStr := r.FormValue("date")
        var date int64
        if dateStr == "" {
            date = time.Now().Unix()
        } else {
            d, err := strconv.ParseInt(dateStr, 10, 64)
            if err != nil {
                http.Error(w, "date deve ser epoch em segundos", http.StatusBadRequest)
                return
            }
            date = d
        }

        _, err = db.Exec(`
            INSERT INTO transactions(user, value, status, date)
            VALUES (?, ?, ?, ?)`, user, value, status, date)
        if err != nil {
            log.Printf("insert error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusCreated)
        fmt.Fprintln(w, "Transação registrada com sucesso")
    }
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

        if !UserMatchesPassword(db,user,pass) {
            http.Error(w, "O usuário não corresponde à senha", http.StatusBadRequest)
            return
        }
        raw := user + "|" + pass
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
//-------------------------------------------------------------------
//  --- INIT ---
// -----------------------------------------------------------------


func InitDB() *sql.DB{
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS users (
        email TEXT NOT NULL PRIMARY KEY,
        name TEXT NOT NULL,
        password TEXT NOT NULL
    );
    `

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'users' created successfully")

	sqlStmt = `
	    CREATE TABLE IF NOT EXISTS categories(
	        user TEXT NOT NULL,
	        name TEXT NOT NULL,
	        type TEXT NOT NULL check(type="in" or type="out"),
	        color TEXT NOT NULL,
	        ICON TEXT NOT NULL,
	        PRIMARY KEY(user,name),
	        FOREIGN KEY(user) REFERENCES users(email)
	        
	    )
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'category' created successfully")

	sqlStmt = `
	    CREATE TABLE IF NOT EXISTS objectives(
	        user TEXT NOT NULL,
	        name TEXT NOT NULL,
	        type TEXT NOT NULL check(type="in" or type="out"),
	        target_value INTEGER NOT NULL,
	        current_value INTEGER NOT NULL,
	        limit_date INTEGER,
	        color TEXT NOT NULL,
	        ICON TEXT NOT NULL,
	        PRIMARY KEY(user,name),
	        FOREIGN KEY(user) REFERENCES users(email)
	        
	    )
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'objectives' created successfully")


	sqlStmt = `
	    CREATE TABLE IF NOT EXISTS transactions(
	        id INTEGER PRIMARY KEY AUTOINCREMENT,
	        user TEXT NOT NULL,
	        description TEXT NOT NULL,
	        value INTEGER NOT NULL,
	        type TEXT NOT NULL check(type="in" or type="out"),
	        category TEXT NOT NULL,
	        date INTEGER NOT NULL,
	        FOREIGN KEY(user) REFERENCES users(email),
	        FOREIGN KEY(category) REFERENCES categories(name)
	    )
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'transactions' created successfully")
	return db
}

func main() {
	
	db := InitDB()
	defer db.Close()
	r := mux.NewRouter()

	r.HandleFunc("/login",Login(db)).Methods("POST")
	r.HandleFunc("/cria_user",CreateUser(db)).Methods("POST")
	r.HandleFunc("/transactionsret",RetTransactions(db)).Methods("POST")
	r.HandleFunc("/transactionspost",PostTransactions(db)).Methods("POST")

	http.ListenAndServe(":8080",r)
	log.Println("Servidor em 127.0.0.1:8080")
}

