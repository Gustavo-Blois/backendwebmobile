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
    if err := db.QueryRow(`SELECT password FROM users WHERE email = ?`, user).Scan(&stored); err != nil {
        return false
    }
    return stored == hash // hash já veio do banco no login; comparação direta é suficiente
}

func UserMatchesPassword(db *sql.DB, user string, pass string) bool{

    var storedHash string
    if err := db.QueryRow(`SELECT password FROM users WHERE email = ?`, user).Scan(&storedHash); err != nil {
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

func alterObjective(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            log.Println("Tentativa de acesso não autorizado \n de:{}\n hash: {}, ok:{}", user, hash, ok)
            return
        }

        if r.Method != http.MethodPost {
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
            return            
        }

        if err := r.ParseForm(); err != nil {
            http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
            return
        }


        // Obtém campos obrigatórios    
            name := r.FormValue("name")
            txType := r.FormValue("type")
            targetValueStr := r.FormValue("target_value")
            currentValueStr := r.FormValue("current_value")
            limitDateStr := r.FormValue("limit_date")
            color := r.FormValue("color")
            icon := r.FormValue("icon")

            new_name := r.FormValue("new_name")
            new_txType := r.FormValue("new_type")
            new_targetValueStr := r.FormValue("new_target_value")
            new_currentValueStr := r.FormValue("new_current_value")
            new_limitDateStr := r.FormValue("new_limit_date")
            new_color := r.FormValue("new_color")
            new_icon := r.FormValue("new_icon")
        // Verifica se todos os campos obrigatórios estão preenchidos
        

        if name == "" || txType == "" || targetValueStr == "" || currentValueStr == "" || color == "" || icon == ""{
            http.Error(w, "Campos obrigatórios: name, target_value, current_value, color, icon", http.StatusBadRequest)
            return
        }

        var limitDate int64
        if limitDateStr == "" {
            limitDate = 0 // sem limite
        } else {
            d, err := strconv.ParseInt(limitDateStr, 10, 64)
            if err != nil {
                http.Error(w, "limit_date deve ser epoch em segundos", http.StatusBadRequest)
                return
            }
            limitDate = d
        }


        if new_name == "" {
            new_name = name // se não for alterado, mantém o mesmo
        }
        if new_txType == "" {
            new_txType = txType // se não for alterado, mantém o mesmo
        }
        if new_targetValueStr == "" {
            new_targetValueStr = targetValueStr // se não for alterado, mantém o mesmo
        }
        if new_currentValueStr == "" {
            new_currentValueStr = currentValueStr // se não for alterado, mantém o mesmo
        }
        var new_limitDate int64
        // se não for alterado, mantém o mesmo
        if new_limitDateStr == "" {
            new_limitDate = limitDate // se não for alterado, mantém o mesmo
        } else {
            d, err := strconv.ParseInt(new_limitDateStr, 10, 64)
            if err != nil {
                http.Error(w, "new_limit_date deve ser epoch em segundos", http.StatusBadRequest)
                return
            }
            limitDate = d
        }
        if new_color == "" {
            new_color = color // se não for alterado, mantém o mesmo
        }
        if new_icon == "" {
            new_icon = icon // se não for alterado, mantém o mesmo
        }

        targetValue, err := strconv.Atoi(targetValueStr)
        if err != nil {
            http.Error(w, "target_value deve ser inteiro", http.StatusBadRequest)
            return
        }

        currentValue, err := strconv.Atoi(currentValueStr)
        if err != nil {
            http.Error(w, "current_value deve ser inteiro", http.StatusBadRequest)
            return
        }


        _, err = db.Exec(`
            UPDATE objectives
            SET name = ?, type = ?, target_value = ?, current_value = ?, limit_date = ?, color = ?, icon = ?
            WHERE user = ? AND name = ? AND type = ? AND target_value = ? AND current_value = ? AND limit_date = ? AND color = ? AND icon = ?`,
            new_name, new_txType, new_targetValueStr, new_currentValueStr, new_limitDate, new_color, new_icon,
            user, name, txType, targetValue, currentValue, limitDate, color, icon)
        if err != nil {
            log.Printf("update error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
        fmt.Fprintln(w, "Objetivo atualizado com sucesso")
    }
}


func Objectives(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        switch r.Method {
        case http.MethodPost:
            if err := r.ParseForm(); err != nil {
                http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
                return
            }

            // Obtém campos obrigatórios
            name := r.FormValue("name")
            txType := r.FormValue("type")
            targetValueStr := r.FormValue("target_value")
            currentValueStr := r.FormValue("current_value")
            limitDateStr := r.FormValue("limit_date")
            color := r.FormValue("color")
            icon := r.FormValue("icon")

            if name == "" || txType == "" || targetValueStr == "" || currentValueStr == "" || color == "" || icon == "" {
                http.Error(w, "Campos obrigatórios: name, target_value, current_value, color, icon", http.StatusBadRequest)
                return
            }

            targetValue, err := strconv.Atoi(targetValueStr)
            if err != nil {
                http.Error(w, "target_value deve ser inteiro", http.StatusBadRequest)
                return
            }

            currentValue, err := strconv.Atoi(currentValueStr)
            if err != nil {
                http.Error(w, "current_value deve ser inteiro", http.StatusBadRequest)
                return
            }

            var limitDate int64
            if limitDateStr == "" {
                limitDate = 0 // sem limite
            } else {
                d, err := strconv.ParseInt(limitDateStr, 10, 64)
                if err != nil {
                    http.Error(w, "limit_date deve ser epoch em segundos", http.StatusBadRequest)
                    return
                }
                limitDate = d
            }

            _, err = db.Exec(`
                INSERT INTO objectives(user, name, type, target_value, current_value, limit_date, color, icon)
                VALUES (?, ?,
 ?, ?, ?, ?, ?, ?)`, user, name, txType, targetValue, currentValue, limitDate, color, icon)
            if err != nil {
                log.Printf("insert error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            w.WriteHeader(http.StatusCreated)
            fmt.Fprintln(w, "Objetivo registrado com sucesso")
        case http.MethodGet:
            rows, err := db.Query(`
                SELECT name, type, target_value, current_value, limit_date, color, icon
                FROM objectives
                WHERE user = ?
                ORDER BY name ASC`, user)
            if err != nil {
                log.Printf("query error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            defer rows.Close()
            type Objective struct {
                Name          string `json:"name"`
                Type          string `json:"type"`
                TargetValue   int    `json:"target_value"`
                CurrentValue  int    `json:"current_value"`
                LimitDate     int64  `json:"limit_date"` // epoch em segundos
                Color         string `json:"color"`
                Icon          string `json:"icon"`
            }
            var objectives []Objective
            for rows.Next() {
                var o Objective
                if err := rows.Scan(&o.Name, &o.Type, &o.TargetValue, &o.CurrentValue, &o.LimitDate, &o.Color, &o.Icon); err != nil {
                    log.Printf("scan error: %v", err)
                    http.Error(w, "Erro interno", http.StatusInternalServerError)
                    return
                }
                objectives = append(objectives, o)
            }
            w.Header().Set("Content-Type", "application/json")
            if err := json.NewEncoder(w).Encode(objectives); err != nil {
                log.Printf("json encode error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
        default:
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
        }
    }
}

func alterCategory(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        if r.Method != http.MethodPost {
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
            return            
        }

        if err := r.ParseForm(); err != nil {
            http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
            return
        }

        // Obtém campos obrigatórios    
        category_name := r.FormValue("category_name")
        txType := r.FormValue("type")
        color := r.FormValue("color")
        icon := r.FormValue("icon")

        new_category_name := r.FormValue("new_category_name")
        new_txType := r.FormValue("new_type")
        new_color := r.FormValue("new_color")
        new_icon := r.FormValue("new_icon")

        // Verifica se todos os campos obrigatórios estão preenchidos
        if category_name == "" || txType == "" || color == "" || icon == ""{
            http.Error(w, "Campos obrigatórios: category_name, type, color, icon", http.StatusBadRequest)
            return
        }
        if new_category_name == "" {
            new_category_name = category_name // se não for alterado, mantém o mesmo
        }
        if new_txType == "" {
            new_txType = txType // se não for alterado, mantém o mesmo
        }
        if new_color == "" {
            new_color = color // se não for alterado, mantém o mesmo
        }
        if new_icon == "" {
            new_icon = icon // se não for alterado, mantém o mesmo
        }

        // Verifica se a categoria existe
        var exists int
        if err := db.QueryRow(`SELECT 1 FROM categories WHERE user = ? AND name = ?`, user, category_name).Scan(&exists); err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, "Categoria não encontrada", http.StatusNotFound)
                return
            }
            log.Printf("db error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }
        // Atualiza a categoria
        _, err := db.Exec(`
            UPDATE categories
            SET name = ?, type = ?, color = ?, icon = ?
            WHERE user = ? AND name = ? AND type = ? AND color = ? AND icon = ?`,
            new_category_name, new_txType, new_color, new_icon,
            user, category_name, txType, color, icon)
        if err != nil {
            log.Printf("update error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
        fmt.Fprintln(w, "Categoria atualizada com sucesso")
    }
}

func Categories(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        switch r.Method {
        case http.MethodPost:
            if err := r.ParseForm(); err != nil {
                http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
                return
            }

            // Obtém campos obrigatórios
            category_name := r.FormValue("category_name")
            txType := r.FormValue("type")
            color := r.FormValue("color")
            icon := r.FormValue("icon")

            if icon == "" || color == "" || (txType != "in" && txType != "out") || category_name == "" {
                http.Error(w, "Campos obrigatórios: description, value, type ('in' ou 'out'), category", http.StatusBadRequest)
                return
            }
            // Verifica se a categoria já existe
            var exists int
            if err := db.QueryRow(`SELECT 1 FROM categories WHERE user = ? AND name = ?`, user, category_name).Scan(&exists); err == nil {
                http.Error(w, "Categoria já existe", http.StatusConflict)
                return
            }
            // Insere a nova categoria
            _, err := db.Exec(`
                INSERT INTO categories(user, name, type, color, icon)
                VALUES (?, ?, ?, ?, ?)`,
                user, category_name, txType, color, icon)
            if err != nil {
                log.Printf("insert error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            w.WriteHeader(http.StatusCreated)
            fmt.Fprintln(w, "Categoria registrada com sucesso")
        case http.MethodGet:
            rows, err := db.Query(`
                SELECT name, type, color, icon
                FROM categories
                WHERE user = ?
                ORDER BY name ASC
            `, user)
            if err != nil {
                log.Printf("query error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            defer rows.Close()
            type Category struct {
                Name  string `json:"name"`
                Type  string `json:"type"`
                Color string `json:"color"`
                Icon  string `json:"icon"`
            }
            var categories []Category
            for rows.Next() {
                var c Category
                if err := rows.Scan(&c.Name, &c.Type, &c.Color, &c.Icon); err != nil {
                    log.Printf("scan error: %v", err)
                    http.Error(w, "Erro interno", http.StatusInternalServerError)
                    return
                }
                categories = append(categories, c)
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(categories)
        default:
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
        }
    }
}


func Transactions(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, hash, ok := parseSessionCookie(r)
        if !ok || !UserMatchesPassword(db, user, hash) {
            http.Error(w, "Não autorizado", http.StatusUnauthorized)
            return
        }

        switch r.Method {
        case http.MethodPost:
            if err := r.ParseForm(); err != nil {
                http.Error(w, "Requisição mal‑formada", http.StatusBadRequest)
                return
            }

            // Obtém campos obrigatórios
            description := r.FormValue("description")
            valueStr := r.FormValue("value")
            txType := r.FormValue("type")
            category := r.FormValue("category")
            dateStr := r.FormValue("date")

            if description == "" || valueStr == "" || (txType != "in" && txType != "out") || category == "" {
                http.Error(w, "Campos obrigatórios: description, value, type ('in' ou 'out'), category", http.StatusBadRequest)
                return
            }

            value, err := strconv.Atoi(valueStr)
            if err != nil {
                http.Error(w, "value deve ser inteiro", http.StatusBadRequest)
                return
            }

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
                INSERT INTO transactions(user, description, value, type, category, date)
                VALUES (?, ?, ?, ?, ?, ?)`,
                user, description, value, txType, category, date)
            if err != nil {
                log.Printf("insert error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }

            w.WriteHeader(http.StatusCreated)
            fmt.Fprintln(w, "Transação registrada com sucesso")

        case http.MethodGet:
            rows, err := db.Query(`
                SELECT id, description, value, type, category, date
                FROM transactions
                WHERE user = ?
                ORDER BY date DESC
            `, user)
            if err != nil {
                log.Printf("query error: %v", err)
                http.Error(w, "Erro interno", http.StatusInternalServerError)
                return
            }
            defer rows.Close()

            type Tx struct {
                ID          int    `json:"id"`
                Description string `json:"description"`
                Value       int    `json:"value"`
                Type        string `json:"type"`
                Category    string `json:"category"`
                Date        int64  `json:"date"`
            }
            var txs []Tx
            for rows.Next() {
                var t Tx
                if err := rows.Scan(&t.ID, &t.Description, &t.Value, &t.Type, &t.Category, &t.Date); err != nil {
                    log.Printf("scan error: %v", err)
                    http.Error(w, "Erro interno", http.StatusInternalServerError)
                    return
                }
                txs = append(txs, t)
            }

            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(txs)

        default:
            http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
        }
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
        email := r.FormValue("email")
        pass := r.FormValue("password")
        if  pass == "" || email == "" {
            http.Error(w, "senha e e-mail são obrigatórios", http.StatusBadRequest)
            return
        }

        if !UserMatchesPassword(db,email,pass) {
            http.Error(w, "O usuário não corresponde à senha", http.StatusBadRequest)
            return
        }
        raw := email + "|" + pass
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
        email := r.FormValue("email")
        pass := r.FormValue("password")
        if user == "" || pass == "" || email == "" {
            http.Error(w, "Usuário, senha e email são obrigatórios", http.StatusBadRequest)
            return
        }

        // Checar se já existe
        var exists int
        if err := db.QueryRow(`SELECT 1 FROM users WHERE email = ?`, email).Scan(&exists); err == nil {
            http.Error(w, "Usuário já existe", http.StatusConflict)
            return
        }

        hash, err := HashPassword(pass)
        if err != nil {
            log.Printf("hash error: %v", err)
            http.Error(w, "Erro interno", http.StatusInternalServerError)
            return
        }

        if _, err := db.Exec(`INSERT INTO users(name,email,password) VALUES (?, ?, ?)`, user, email, hash); err != nil {
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
	        user TEXT NOT NULL,
	        name TEXT NOT NULL,
	        type TEXT NOT NULL check(type="in" or type="out"),
	        color TEXT NOT NULL,
	        ICON TEXT NOT NULL,
	        FOREIGN KEY(user) REFERENCES users(email)
            UNIQUE(user, name, type, color, icon)
	    )
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Table 'category' created successfully")

	sqlStmt = `
	    CREATE TABLE IF NOT EXISTS objectives(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
	        user TEXT NOT NULL,
	        name TEXT NOT NULL,
	        type TEXT NOT NULL,
	        target_value INTEGER NOT NULL,
	        current_value INTEGER NOT NULL,
	        limit_date INTEGER,
	        color TEXT NOT NULL,
	        ICON TEXT NOT NULL,
	        FOREIGN KEY(user) REFERENCES users(email)
            UNIQUE(user, name, type, target_value, current_value, limit_date, color, icon)
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
	r.HandleFunc("/transactions",Transactions(db)).Methods("POST", "GET")
    r.HandleFunc("/categories",Categories(db)).Methods("POST", "GET")
    r.HandleFunc("/objectives",Objectives(db)).Methods("POST", "GET")
    r.HandleFunc("/alter_objective", alterObjective(db)).Methods("POST")
    r.HandleFunc("/alter_category", alterCategory(db)).Methods("POST")
    r.Use(mux.CORSMethodMiddleware(r)) // Habilita CORS para todas as rotas


	http.ListenAndServe(":8080",r)
	log.Println("Servidor em 127.0.0.1:8080")
}

