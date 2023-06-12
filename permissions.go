package permissions

import (
	"sync"
)

var (

	// use this field to read module independent permissions
	GlobalModule = "global"
	AdminName    = "admin"
)

// Permissions represents a
type Permissions struct {
	Permissions map[string][]string `bson:"perms,inline"`
	mu          sync.RWMutex
}

func NewPermissions() *Permissions {
	return &Permissions{Permissions: make(map[string][]string), mu: sync.RWMutex{}}
}

func NewPermissionsFromMap(perms map[string][]string) *Permissions {
	return &Permissions{Permissions: perms, mu: sync.RWMutex{}}
}

///////////////////////////////////////////////////////////////////
/////////////////////////  Getters  ///////////////////////////////
///////////////////////////////////////////////////////////////////

// HasPerm checks if entity has a particular permission
// Use GlobalModule field to read module independent permissions
//
// Please Note that an empty module will be replaced by GlobalModule
// and in case of an empty perm, HasPerm will always return true
func (p *Permissions) HasPerm(module string, perm string) bool {
	if perm == "" {
		return true
	}
	if module == "" {
		module = GlobalModule
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	perms, ok := p.Permissions[module]
	if !ok {
		return false
	}
	for _, per := range perms {
		if per == perm {
			return true
		}
	}
	return false
}

// Same as p.HasPerm(GlobalModule, AdminName)
func (p *Permissions) IsAdmin() bool {
	return p.HasPerm(GlobalModule, AdminName)
}

// Same as p.HasPerm(module, AdminName)
func (p *Permissions) IsModuleAdmin(module string) bool {
	return p.HasPerm(module, AdminName)
}

// Same as p.HasPerm(GlobalModule, perm) or p.HasPerm("", perm)
func (p *Permissions) HasGlobalPerm(perm string) bool {
	return p.HasPerm(GlobalModule, perm)
}

///////////////////////////////////////////////////////////////////
//////////////////////////  Adders  ///////////////////////////////
///////////////////////////////////////////////////////////////////

// AddPerm is idempotent and if module is empty it will be replaced by GlobalModule
func (p *Permissions) AddPerm(module string, perm ...string) {
	if len(perm) == 0 || perm[0] == "" {
		return
	}
	if module == "" {
		module = GlobalModule
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	perms, ok := p.Permissions[module]
	if !ok {
		p.Permissions[module] = append(perms, perm...) // // append(nil, val) initiates a new array of type val
		return
	}

	for _, current := range perm { // append each permission
		if current == "" {
			continue
		}

		for _, pe := range perms {
			if pe == current {
				// user already has permission
				return
			}
		}
		p.Permissions[module] = append(perms, current)
	}
}

// This is the same as p.AddPerm("", perm)
func (p *Permissions) AddGlobalPerm(perm string) {
	p.AddPerm(GlobalModule, perm)
}

func (p *Permissions) SetAdmin() {
	p.AddPerm(GlobalModule, AdminName)
}

func (p *Permissions) SetModuleAdmin(module string) {
	p.AddPerm(module, AdminName)
}

///////////////////////////////////////////////////////////////////
///////////////////////////  Removers  ////////////////////////////
///////////////////////////////////////////////////////////////////

// RemovePerm is idempotent and if module is empty it will be replaced by GlobalModule
func (p *Permissions) RemovePerm(mod string, perm string) {
	if perm == "" {
		return
	}
	if mod == "" {
		mod = GlobalModule
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	perms, ok := p.Permissions[mod]
	if !ok {
		// entity doesn't have module init so can't have permission
		return
	}

	for i, pe := range perms {
		if pe == perm {
			//order not important
			perms[i] = perms[len(perms)-1]
			p.Permissions[mod] = perms[:len(perms)-1]
			return
		}
	}
}

func (p *Permissions) RemoveAdmin() {
	p.RemovePerm(GlobalModule, AdminName)
}

func (p *Permissions) RemoveModuleAdmin(module string) {
	p.RemovePerm(module, AdminName)
}

// RemoveAll removes all permissions entity has
func (p *Permissions) RemoveAll() {
	p.mu.Lock()
	p.Permissions = map[string][]string{}
	p.mu.Unlock()
}

// RemoveAllButAdmin removes all permissions entity has except its global
// admin permission (only if it already has it)
func (p *Permissions) RemoveAllButAdmin() {
	admin := p.IsAdmin()
	p.mu.Lock()
	p.Permissions = map[string][]string{}
	p.mu.Unlock()
	if admin {
		p.SetAdmin()
	}
}

// RemoveAll removes all permissions entity has from a module
func (p *Permissions) RemoveAllModule(mod string) {
	p.mu.Lock()
	delete(p.Permissions, mod)
	p.mu.Unlock()
}

// RemoveAll removes all permissions an entity has form a module except module
// admin permission (only if it already has it)
func (p *Permissions) RemoveAllModuleButKeepAdmin(mod string) {
	admin := p.IsModuleAdmin(mod)
	p.mu.Lock()
	_, ok := p.Permissions[mod]
	if ok {
		// change to a switch statement ?
		if admin {
			p.Permissions[mod] = p.Permissions[mod][:1]
			p.Permissions[mod][0] = AdminName
		} else {
			p.Permissions[mod] = p.Permissions[mod][:0]
		}
	}
	p.mu.Unlock()
}

// Please Note that calling any modifying Permissions method (add or remove) inside f will result in a deadlock
func (p *Permissions) ForEach(f func(mod string, perm string)) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for mod, perms := range p.Permissions {
		for _, perm := range perms {
			f(mod, perm)
		}
	}
}

// FIXME might be broken (not tested)
func (p *Permissions) Filter(f func(mod string, perm string) bool) {
	p.mu.Lock()
	defer p.mu.RUnlock()

	for mod, perms := range p.Permissions {
		for i := 0; i < len(perms); i++ {
			if !f(mod, perms[i]) {
				perms[i] = perms[len(perms)-1]
				p.Permissions[mod] = perms[:len(perms)-1]
				i--
			}
		}
	}
}

func (p *Permissions) CopyMap() map[string][]string {
	var m = map[string][]string{}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for k, v := range p.Permissions {
		m[k] = append(m[k], v...)
	}
	return m
}

func (p *Permissions) Copy() *Permissions {
	return &Permissions{
		Permissions: p.CopyMap(),
		mu:          sync.RWMutex{},
	}
}
