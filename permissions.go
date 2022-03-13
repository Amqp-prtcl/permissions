package permissions

import "sync"

const (

	// use this field to read module independent permissions
	GlobalModule = "global"
	AdminName    = "admin"
)

type Permissions struct {
	Permissions map[string][]string
	mu          sync.RWMutex
}

func (p *Permissions) IsAdmin() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// this function cannot use HasPerm() as it will result in an infinite recursion
	// so it needs to be coded manually
	perms, ok := p.Permissions[GlobalModule]
	if !ok {
		return false
	}
	for _, per := range perms {
		if per == AdminName {
			return true
		}
	}
	return false
}

func (p *Permissions) IsModuleAdmin(mod string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// this function cannot use HasPerm() as it will result in an infinite recursion
	// so it needs to be coded manually
	if p.IsAdmin() {
		return true
	}

	perms, ok := p.Permissions[mod]
	if !ok {
		return false
	}
	for _, per := range perms {
		if per == AdminName {
			return true
		}
	}
	return false
}

// HasAdmin checks is entity has a particular permission
// Use GlobalModule field to read module independent permissions
func (p *Permissions) HasPerm(mod string, perm string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.IsAdmin() {
		return true
	}
	if p.IsModuleAdmin(mod) {
		return true
	}

	perms, ok := p.Permissions[mod]
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

func (p *Permissions) HasGlobalPerm(perm string) bool {
	return p.HasPerm(GlobalModule, perm)
}

// AddPerm is idempotent
func (p *Permissions) AddPerm(mod string, perm string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	perms, ok := p.Permissions[mod]
	if ok {
		// entity already has some permissions, so we need to check that it doesn't already have it before appending it
		for _, pe := range perms {
			if pe == perm {
				// user already has permission
				return
			}
		}
	}
	p.Permissions[mod] = append(perms, perm) // append(nil, val) initiates a new array of type val
}

func (p *Permissions) AddGlobalPerm(perm string) {
	p.AddPerm(GlobalModule, perm)
}

func (p *Permissions) SetAdmin() {
	p.AddPerm(GlobalModule, AdminName)
}

func (p *Permissions) SetModuleAdmin(mod string) {
	p.AddPerm(mod, AdminName)
}

func (p *Permissions) RemovePerm(mod string, perm string) {
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

func (p *Permissions) RemoveModuleAdmin(mod string) {
	p.RemovePerm(mod, AdminName)
}

// RemoveAll removes all permissions entity has
func (p *Permissions) RemoveAll() {
	p.mu.Lock()
	p.Permissions = map[string][]string{}
	p.mu.Unlock()
}

// RemoveAllButAdmin removes all permissions entity has except global admin permission (only if entity initially has it)
func (p *Permissions) RemoveAllButAdmin() {
	admin := p.IsAdmin()
	p.mu.Lock()
	p.Permissions = map[string][]string{}
	p.mu.Unlock()
	if admin {
		p.SetAdmin()
	}
}

// RemoveAll removes all permissions entity has form a module
func (p *Permissions) RemoveAllModule(mod string) {
	p.mu.Lock()
	_, ok := p.Permissions[mod]
	if ok {
		p.Permissions[mod] = []string{}
	}
	p.mu.Unlock()
}

// RemoveAll removes all permissions entity has form a module except module admin permission (only if entity initially has it)
func (p *Permissions) RemoveAllModuleButAdmin(mod string) {
	admin := p.IsModuleAdmin(mod)
	p.mu.Lock()
	_, ok := p.Permissions[mod]
	if ok {
		// change to a switch statement ?
		if admin {
			p.Permissions[mod] = append(p.Permissions[mod], AdminName)
		} else {
			p.Permissions[mod] = []string{}
		}
	}
	p.mu.Unlock()
}

// interacting with p inside of f will cause a deadlock
func (p *Permissions) ForEach(f func(mod string, perm string)) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for mod, perms := range p.Permissions {
		for _, perm := range perms {
			f(mod, perm)
		}
	}
}

func (p *Permissions) Copy() map[string][]string {
	var m = map[string][]string{}
	p.ForEach(func(mod, perm string) {
		m[mod] = append(m[mod], perm)
	})
	return m
}
