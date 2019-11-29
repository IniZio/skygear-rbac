package enforcer

import (
	"log"
	"skygear-rbac/functions"
	"time"

	"github.com/casbin/casbin/v2"
	xormadapter "github.com/casbin/xorm-adapter"
	"github.com/lib/pq"
)

// Config configuration for initializing casbin Enforcer
type Config struct {
	Model    string
	File     string
	Database string
}

const (
	enforcerInitializeRetryCount = 3
)

// NewEnforcer creates and return a casbin Enforcer
func NewEnforcer(enforcerConfig Config) (*casbin.Enforcer, error) {
	var enforcer *casbin.Enforcer
	var err error
	if len(enforcerConfig.Database) != 0 {
		params, err := pq.ParseURL(enforcerConfig.Database)
		if err != nil {
			return nil, err
		}
		adapter, err := func() (*xormadapter.Adapter, error) {
			var err error
			for i := 0; i < enforcerInitializeRetryCount; i++ {
				a, e := xormadapter.NewAdapter("postgres", params)
				if e == nil {
					return a, nil
				}
				err = e
				log.Println("🔌 RBAC failed to connect db, retrying...")
				time.Sleep(time.Second)
			}
			return nil, err
		}()
		if err != nil {
			return nil, err
		}
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, adapter)
		if err != nil {
			return nil, err
		}
	} else if len(enforcerConfig.File) != 0 {
		log.Printf("📒 RBAC is using CSV storage %s \n", enforcerConfig.File)
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model, enforcerConfig.File)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("🧠 RBAC does not detect any storage setting, using In-Memory")
		enforcer, err = casbin.NewEnforcer(enforcerConfig.Model)
		if err != nil {
			return nil, err
		}
	}

	enforcer.AddFunction("isAssignedRoleInParentDomain", functions.CreateIsAssignedRoleInParentDomain(enforcer))

	return enforcer, nil
}
