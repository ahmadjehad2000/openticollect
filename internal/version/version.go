// Package version exposes the build version, injected at link time.
package version

// Version is overridden via -ldflags "-X openticollect/internal/version.Version=...".
var Version = "dev"

// String is the User-Agent / display form.
func String() string { return "openTIcollect/" + Version }
