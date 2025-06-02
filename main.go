package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
)
 
func Login() func( http.ResponseWriter, *http.Request){
	return func(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	user := r.FormValue("user")
	password := r.FormValue("password")

	if user == "admin" && password == "admin" {
		http.Redirect(w,r,"http://localhost:8080/admin", 302)
	} else {
	fmt.Fprintf(w,"Nuh Uh")
	}
	}
}

func admin(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w,"Bem vindo à area do admin");
}
func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login",Login()).Methods("POST")

	r.HandleFunc("/admin",admin).Methods("GET")
	http.ListenAndServe(":8080",r)
}
