# Permissions

## Installation

To use this library simply run the following command in your Go module
```
go get http://github.com/Amqp-prtcl/permissions
```

## Usage

This library implements a permission system that allows to add to any entity tags that represent permissions.

A permission entry has a module name and a permission name that can be added, found, or removed.

### Create a permission

To use permissions you must first attribute a `Permissions` to an entity.
This can be done by doing the following:
```go
var perms = permissions.NewPermissions()
// or if you already have a set of permissions
var rawPerms = map[string][]string {
	"module1":{"perm1", "perm2"},
	"module2":{"perm1", "perm2"},
}
perms = permissions.NewPermissionsFromMap(rawPerms)
```

### Add permissions

You can then add permissions using the `AddPerm` method.
However please note that no permission entry will be added is perm is empty and if module is empty, it will be replaced by `GlobalModule`.

### Check permissions

You can check if an entity has a particular permission with the `HasPerm`.
Similarly to `AddPerm`, an empty module name will be replaced by `GlobalModule`.

**Note**: An empty permission will ALWAYS return true.

### RemovePermission

You can remove permissions with `RemovePerm` and an empty module name will be replaced by the `GlobalModule`

**Note**: `AddPerm`, `HasPerm`, `RemovePerm` are all idempotent.

## Admin permissions

The library is made to recognize the AdminName with the `AdminName` variable that can be edited. However note that doing so will prevent all users that were previously admin and don't have the new Admin permission from accessing admin functionalities.