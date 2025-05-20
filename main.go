package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
)
 
func home(w http.ResponseWriter, r *http.Request){
	vars := mux.Vars(r);
	fmt.Fprintf(w,"%s",vars)
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/",home).Methods("GET")

	http.ListenAndServe(":80",r)
}
