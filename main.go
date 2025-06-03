package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"database/sql"
	"crypto/sha256"
)
 
func Login(db *sql.DB) func( http.ResponseWriter, *http.Request){
	return func(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := r.FormValue("user")
	password := r.FormValue("password")
	h := sha256.New()
	h.Write([]byte(password))
	hashed_password := h.Sum(nil)
	var row int
	err := db.QueryRow("SELECT EXISTS(SELECT 1 from users where password = ? AND name = ?)",hashed_password,user).Scan(&row)
	if err != nil {
		log.Printf("Erro ao selecionar usuário na tabela")
		log.Fatal(err)
	} 
	if row == 1 {
		log.Printf("deu certo")
	} else {
		log.Printf("deu errado")
	}
	
  }
}

func CreateUser(db *sql.DB) func(http.ResponseWriter, *http.Request){
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user := r.FormValue("user")
		password := r.FormValue("Password")
		h := sha256.New()
		h.Write([]byte(password))
		hashed_password :=  h.Sum(nil)
		_, err := db.Exec("INSERT INTO users(name,password) VALUES (?,?)",user,hashed_password)
		if err != nil {
			log.Fatal(err)
		}
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
        password TEXT
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
