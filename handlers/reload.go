package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	casbin "github.com/casbin/casbin/v2"

	"skygear-rbac/constants"
	"skygear-rbac/enforcer"
)

func replace(enforcer **casbin.Enforcer, newEnforcer *casbin.Enforcer) {
	*enforcer = newEnforcer
}

type ReloadHandler struct {
	Enforcer       *casbin.Enforcer
	EnforcerConfig enforcer.Config
}

type ReloadInput struct {
	Domains         []DomainInput        `json:"domains,omitempty" schema:"domains,omitempty"`
	RoleAssignments RoleAssignmentsInput `json:"roleAssignments,omitempty" schema:"roleAssignments,omitempty"`
	Policies        PoliciesInput        `json:"policies,omitempty" schema:"policies,omitempty"`
}

func (h *ReloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var err error

		input := ReloadInput{}
		json.NewDecoder(r.Body).Decode(&input)

		newEnforcer, err := enforcer.NewEnforcer(h.EnforcerConfig)
		if err != nil {
			log.Fatal(err)
			w.WriteHeader(500)
			return
		}

		// Saves domain inheritance
		for _, domainInput := range input.Domains {
			if len(domainInput.Parent) == 0 {
				domainInput.Parent = "root"
			}

			_, err = newEnforcer.AddNamedGroupingPolicy("g", domainInput.Parent, domainInput.Domain, constants.IsDomain)

			if err != nil {
				log.Fatal(err)
				w.WriteHeader(500)
				return
			}

			if len(domainInput.SubDomains) != 0 {
				for _, subdomain := range domainInput.SubDomains {
					_, err = newEnforcer.AddNamedGroupingPolicy("g", domainInput.Domain, subdomain, constants.IsDomain)
					if err != nil {
						log.Fatal(err)
						w.WriteHeader(500)
						return
					}
				}
			}
		}

		// Saves role assignment
		for _, roleAssignmentInput := range input.RoleAssignments {
			if len(roleAssignmentInput.Subject) == 0 {
				roleAssignmentInput.Subject = constants.NoSubject
			}

			if roleAssignmentInput.Unassign {
				_, err = newEnforcer.RemoveNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(500)
					return
				}
			} else {
				_, err = newEnforcer.AddNamedGroupingPolicy("g", roleAssignmentInput.Subject, roleAssignmentInput.Role, roleAssignmentInput.Domain)
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(500)
					return
				}
			}
		}

		// Saves access rights
		for _, policyInput := range input.Policies {
			if policyInput.Effect == "deny" {
				_, err = newEnforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "deny")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(500)
					return
				}
			} else {
				_, err := newEnforcer.AddPolicy(policyInput.Domain, policyInput.Subject, policyInput.Object, policyInput.Action, "allow")
				if err != nil {
					log.Fatal(err)
					w.WriteHeader(500)
					return
				}
			}
		}

		replace(&h.Enforcer, newEnforcer)

		newEnforcer.SavePolicy()
	}
}
