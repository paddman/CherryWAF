package waf

import (
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

func requestTargets(r *http.Request, body []byte) map[string]string {
	return map[string]string{
		"method":  strings.ToUpper(r.Method),
		"path":    normalizePath(r.URL.EscapedPath()),
		"query":   normalizeQuery(r.URL.RawQuery),
		"headers": normalizeHeaders(r.Header),
		"cookies": normalizeCookies(r.Cookies()),
		"body":    normalizeText(string(body), true),
	}
}

func normalizePath(value string) string {
	value = decodePath(value, 3)
	return normalizeText(value, false)
}

func normalizeQuery(value string) string {
	value = decodeQuery(value, 3)
	return normalizeText(value, false)
}

func decodePath(value string, rounds int) string {
	for i := 0; i < rounds; i++ {
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return value
}

func decodeQuery(value string, rounds int) string {
	for i := 0; i < rounds; i++ {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return value
}

func normalizeText(value string, queryDecode bool) string {
	value = strings.ToValidUTF8(value, "�")
	if queryDecode {
		value = decodeQuery(value, 2)
	}
	value = html.UnescapeString(value)
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return ' '
		}
		return r
	}, value)
	return strings.ToLower(value)
}

func normalizeHeaders(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, key := range keys {
		b.WriteString(strings.ToLower(key))
		b.WriteByte(':')
		for _, value := range headers.Values(key) {
			b.WriteString(normalizeText(value, true))
			b.WriteByte(' ')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func normalizeCookies(cookies []*http.Cookie) string {
	var b strings.Builder
	for _, cookie := range cookies {
		b.WriteString(strings.ToLower(cookie.Name))
		b.WriteByte('=')
		b.WriteString(normalizeText(cookie.Value, true))
		b.WriteByte(';')
	}
	return b.String()
}
