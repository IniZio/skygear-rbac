package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	filters "robpike.io/filter"
)

const NoSubject = "__nosubject__"

func RoleAssignmentsFromCasbin(raw [][]string) []RoleAssignment {
	ras := []RoleAssignment{}

	for _, s := range raw {
		ra := RoleAssignment{
			Subject: s[0],
			Role:    s[1],
			Domain:  s[2],
		}

		if ra.Subject == NoSubject {
			ra.Subject = ""
		}
		ras = append(ras, ra)

	}
	return ras
}

type RoleAssignment struct {
	Subject string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role    string `json:"role,omitempty" schema:"role,omitempty"`
	Domain  string `json:"domain" schema:"domain"`
}

type RoleAssignmentsInput []RoleAssignmentInput

type RoleAssignmentInput struct {
	Subject  string `json:"subject,omitempty" schema:"subject,omitempty"`
	Role     string `json:"role,omitempty" schema:"role,omitempty"`
	Domain   string `json:"domain" schema:"domain"`
	Unassign bool   `json:"unassign,omitempty" schema:"unassign,omitempty"`
}

type RoleHandler struct {
	Enforcer *casbin.Enforcer
}

func (h *RoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	subject := mux.Vars(r)["subject"]

	switch r.Method {
	case http.MethodGet:
		if os.Getenv("ENV") != "development" {
			err := h.Enforcer.LoadPolicy()
			if err != nil {
				log.Fatal(err)
				w.WriteHeader(502)
			}
		}
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())
		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(subject) != 0 {
			filter.Subject = subject
		}

		if len(filter.Subject) == 0 {
			filter.Subject = NoSubject
		}

		raw := h.Enforcer.GetFilteredGroupingPolicy(0, filter.Subject)
		roleAssignments := filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
			return (len(filter.Domain) == 0 || filter.Domain == ra.Domain)
		})
		js, _ := json.Marshal(roleAssignments)
		w.Write(js)
	case http.MethodPost:
		if os.Getenv("ENV") != "development" {
			err := h.Enforcer.LoadPolicy()
			if err != nil {
				log.Fatal(err)
				w.WriteHeader(502)
			}
		}
		inputs := RoleAssignmentsInput{}
		json.NewDecoder(r.Body).Decode(&inputs)

		roleAssignments := []RoleAssignment{}

		for _, input := range inputs {
			if len(domain) != 0 {
				input.Domain = domain
			}

			if len(subject) != 0 {
				input.Subject = subject
			}

			if len(input.Subject) == 0 {
				input.Subject = NoSubject
			}

			if input.Unassign {
				h.Enforcer.RemoveGroupingPolicy(input.Subject, input.Role, input.Domain)
			} else {
				h.Enforcer.AddGroupingPolicy(input.Subject, input.Role, input.Domain)
			}

			h.Enforcer.AddNamedGroupingPolicy("g3", input.Role, "role", input.Domain)
			// if input.Subject == NoSubject {
			// 	h.Enforcer.RemoveNamedGroupingPolicy("g4", input.Role, "disabled", input.Domain)
			// }
			raw := h.Enforcer.GetFilteredGroupingPolicy(0, input.Subject)
			for _, assignment := range filters.Choose(RoleAssignmentsFromCasbin(raw), func(ra RoleAssignment) bool {
				return (len(input.Domain) == 0 || input.Domain == ra.Domain)
			}).([]RoleAssignment) {
				roleAssignments = append(roleAssignments, assignment)
			}
		}
		h.Enforcer.SavePolicy()

		js, _ := json.Marshal(roleAssignments)
		w.Write(js)
	case http.MethodDelete:
		if os.Getenv("ENV") != "development" {
			err := h.Enforcer.LoadPolicy()
			if err != nil {
				log.Fatal(err)
				w.WriteHeader(502)
			}
		}
		decoder := schema.NewDecoder()
		filter := RoleAssignment{}
		err := decoder.Decode(&filter, r.URL.Query())

		if err != nil {
			panic(err)
		}

		if len(domain) != 0 {
			filter.Domain = domain
		}

		if len(subject) != 0 {
			filter.Subject = subject
		}

		if len(filter.Subject) == 0 {
			filter.Subject = NoSubject
		}

		h.Enforcer.RemoveGroupingPolicy(filter.Subject, filter.Role, filter.Domain)

		if filter.Subject == NoSubject {
			h.Enforcer.AddNamedGroupingPolicy("g4", filter.Subject, "disabled", filter.Domain)
		}

		h.Enforcer.SavePolicy()
	}
}
