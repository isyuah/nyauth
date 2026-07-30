package settings

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
)

var siteBannerMarkdown = goldmark.New(
	goldmark.WithRendererOptions(html.WithHardWraps()),
)

// RenderSiteBannerMarkdown validates site banner Markdown and returns HTML
// from Goldmark's safe renderer. Raw HTML and images are intentionally invalid.
func RenderSiteBannerMarkdown(value string) (string, error) {
	source := []byte(value)
	document := siteBannerMarkdown.Parser().Parse(text.NewReader(source))
	if err := ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch typed := node.(type) {
		case *ast.RawHTML, *ast.HTMLBlock:
			return ast.WalkStop, errors.New("site banner Markdown must not contain raw HTML")
		case *ast.Image:
			return ast.WalkStop, errors.New("site banner Markdown must not contain images")
		case *ast.Link:
			if !validSiteBannerURL(string(typed.Destination)) {
				return ast.WalkStop, errors.New("site banner Markdown links must use a root-relative path or absolute HTTPS URL")
			}
		case *ast.AutoLink:
			if !validSiteBannerURL(string(typed.URL(source))) {
				return ast.WalkStop, errors.New("site banner Markdown links must use a root-relative path or absolute HTTPS URL")
			}
		}
		return ast.WalkContinue, nil
	}); err != nil {
		return "", err
	}

	var output bytes.Buffer
	if err := siteBannerMarkdown.Renderer().Render(&output, source, document); err != nil {
		return "", fmt.Errorf("rendering site banner Markdown: %w", err)
	}
	return output.String(), nil
}
