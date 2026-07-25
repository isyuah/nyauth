//go:build !noembed

package nyauth

import "embed"

//go:embed all:web/build
var WebFS embed.FS
