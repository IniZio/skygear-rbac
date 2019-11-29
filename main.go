package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"skygear-rbac/config"
	"skygear-rbac/enforcer"
	handlers "skygear-rbac/handlers"

	"github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
)

func reloadEnforcer(enforcer *casbin.Enforcer) error {
	return enforcer.LoadPolicy()
}

func main() {
	var enforcerConfig = enforcer.Config{
		Model:    "./model.conf",
		Database: config.LoadFromEnv("DATABASE_URL", ""),
		File:     config.LoadFromEnv("POLICY_PATH", ""),
	}

	if config.LoadFromEnv("ENV", "") == "development" {
		enforcerConfig = enforcer.Config{
			Model: "./model.conf",
			File:  "./policy.csv",
		}
	}

	enforcer, err := enforcer.NewEnforcer(enforcerConfig)
	if err != nil {
		log.Panic(err)
	}
	err = reloadEnforcer(enforcer)
	if err != nil {
		log.Panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	// For reloading policy / model if it is updated externally e.g. Directly updated rules in database
	r.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		err := reloadEnforcer(enforcer)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(502)
		}
		log.Println("♻ RBAC reloaded enforcer")
	})
	r.Handle("/enforce", &handlers.EnforceHandler{Enforcer: enforcer})
	r.Handle("/{domain}/subject/{subject}/role", &handlers.RoleHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/policy", &handlers.PolicyHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/subject", &handlers.SubjectHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role/{role}/user", &handlers.UserHandler{Enforcer: enforcer})
	r.Handle("/{domain}/role", &handlers.RoleHandler{Enforcer: enforcer})
	r.Handle("/{domain}/policy", &handlers.PolicyHandler{Enforcer: enforcer})
	r.Handle("/{domain}", &handlers.DomainHandler{Enforcer: enforcer})
	r.Handle("/{domain}/subdomain/{subdomain}", &handlers.DomainHandler{Enforcer: enforcer})

	log.Println("🚀 RBAC listening on 6543")
	log.Fatal(http.ListenAndServe(":6543", r))
}
