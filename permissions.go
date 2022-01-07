package permissions

const (
	null Permission = iota
	Owner
	Admin
	Mod
	User
	Visitor
)

type Permission int

func (p Permission) IsOwner() bool {
	return p == Owner
}

func (p Permission) IsAdmin() bool {
	return p == Admin
}

func (p Permission) IsMod() bool {
	return p == Mod
}

func (p Permission) IsUser() bool {
	return p == User
}

func (p Permission) IsVisitor() bool {
	return p == Visitor
}

func (p Permission) Is(lvl Permission) bool {
	return p == lvl
}

func (p Permission) CanOwner() bool {
	return p == Owner
}

func (p Permission) CanAdmin() bool {
	return p == Owner || p == Admin
}

func (p Permission) CanMod() bool {
	return p == Owner || p == Admin || p == Mod
}

func (p Permission) CanUser() bool {
	return p == Owner || p == Admin || p == Mod || p == User
}

func (p Permission) CanVisistor() bool {
	return p == Owner || p == Admin || p == Mod || p == User || p == Visitor
}

func (p Permission) Can(lvl Permission) bool {
	return p > 0 && p <= lvl
}
