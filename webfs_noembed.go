//go:build noembed

package nyauth

import "embed"

// WebFS is empty when built with the noembed tag.
var WebFS embed.FS
