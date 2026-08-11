package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/paddman/CherryWAF/internal/config"
)

type compiledContentRoute struct {
	config        config.ContentRoute
	methods       map[string]struct{}
	pathPattern   *regexp.Regexp
	headerPattern *regexp.Regexp
	queryPattern  *regexp.Regexp
}

func compileContentRoutes(routes []config.ContentRoute) ([]compiledContentRoute, error) {
	compiled := make([]compiledContentRoute, 0, len(routes))
	for _, route := range routes {
		if !route.Enabled {
			continue
		}
		item := compiledContentRoute{config: route, methods: make(map[string]struct{})}
		for _, method := range route.Methods {
			item.methods[strings.ToUpper(strings.TrimSpace(method))] = struct{}{}
		}
		var err error
		if route.PathPattern != "" {
			item.pathPattern, err = regexp.Compile(route.PathPattern)
			if err != nil {
				return nil, fmt.Errorf("content route %q path pattern: %w", route.Name, err)
			}
		}
		if route.HeaderPattern != "" {
			item.headerPattern, err = regexp.Compile(route.HeaderPattern)
			if err != nil {
				return nil, fmt.Errorf("content route %q header pattern: %w", route.Name, err)
			}
		}
		if route.QueryPattern != "" {
			item.queryPattern, err = regexp.Compile(route.QueryPattern)
			if err != nil {
				return nil, fmt.Errorf("content route %q query pattern: %w", route.Name, err)
			}
		}
		compiled = append(compiled, item)
	}
	return compiled, nil
}

func (route compiledContentRoute) matches(request *http.Request) bool {
	if len(route.methods) > 0 {
		if _, found := route.methods[strings.ToUpper(request.Method)]; !found {
			return false
		}
	}
	if route.config.PathPrefix != "" && !strings.HasPrefix(request.URL.Path, route.config.PathPrefix) {
		return false
	}
	if route.pathPattern != nil && !route.pathPattern.MatchString(request.URL.Path) {
		return false
	}
	if route.headerPattern != nil && !route.headerPattern.MatchString(request.Header.Get(route.config.HeaderName)) {
		return false
	}
	if route.queryPattern != nil && !route.queryPattern.MatchString(request.URL.Query().Get(route.config.QueryName)) {
		return false
	}
	return true
}
