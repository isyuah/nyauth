package buildinfo

// Version and Commit are injected by the release build. Development builds
// deliberately use stable, non-empty values so diagnostics never guess.
var (
	Version = "0.7.0-dev"
	Commit  = "unknown"
)
