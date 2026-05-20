// Package web embeds the server-rendered templates and static assets.
package web

import "embed"

//go:embed templates
var Templates embed.FS

//go:embed static
var Static embed.FS
