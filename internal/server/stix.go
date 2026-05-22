package server

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openticollect/internal/models"
	"openticollect/internal/store"
)

// stixBundle is a STIX 2.1 bundle envelope.
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

// stixObject covers the two STIX SDO types this export emits: "indicator"
// and "vulnerability". Empty fields are omitted so each object stays valid.
type stixObject struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	Name        string   `json:"name,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	PatternType string   `json:"pattern_type,omitempty"`
	ValidFrom   string   `json:"valid_from,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

// stixNamespace is a fixed UUID used to derive deterministic UUIDv5 object IDs.
var stixNamespace = [16]byte{
	0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// uuidV5 derives an RFC-4122 v5 (SHA-1) UUID from the namespace and name, so
// re-exporting the same indicator yields a stable STIX ID.
func uuidV5(name string) string {
	h := sha1.New()
	h.Write(stixNamespace[:])
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// stixPattern maps an ioc kind to a STIX 2.1 comparison-expression pattern.
// The bool is false when the kind has no indicator pattern (e.g. CVE).
func stixPattern(kind, value string) (string, bool) {
	v := strings.ReplaceAll(value, "'", "")
	switch kind {
	case "ipv4":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", v), true
	case "ipv6":
		return fmt.Sprintf("[ipv6-addr:value = '%s']", v), true
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", v), true
	case "url":
		return fmt.Sprintf("[url:value = '%s']", v), true
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", v), true
	case "md5":
		return fmt.Sprintf("[file:hashes.'MD5' = '%s']", v), true
	case "sha1":
		return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", v), true
	case "sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", v), true
	case "btc", "eth":
		return fmt.Sprintf("[x-cryptocurrency:value = '%s']", v), true
	default:
		return "", false
	}
}

// buildSTIXBundle converts stored indicators into a STIX 2.1 bundle. CVE
// indicators become STIX `vulnerability` objects; everything else becomes a
// STIX `indicator` object carrying a pattern.
func buildSTIXBundle(inds []models.Indicator) stixBundle {
	objs := make([]stixObject, 0, len(inds))
	for _, in := range inds {
		ts := in.CreatedAt.UTC().Format(time.RFC3339)
		if ts == "0001-01-01T00:00:00Z" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}
		if in.Kind == "cve" {
			name := strings.ToUpper(in.Value)
			objs = append(objs, stixObject{
				Type: "vulnerability", SpecVersion: "2.1",
				ID:      "vulnerability--" + uuidV5("vulnerability|"+name),
				Created: ts, Modified: ts, Name: name,
			})
			continue
		}
		pattern, ok := stixPattern(in.Kind, in.Value)
		if !ok {
			continue
		}
		objs = append(objs, stixObject{
			Type: "indicator", SpecVersion: "2.1",
			ID:      "indicator--" + uuidV5(in.Kind+"|"+in.Value),
			Created: ts, Modified: ts, ValidFrom: ts,
			Name:        in.Kind + " " + in.Value,
			Pattern:     pattern,
			PatternType: "stix",
			Labels:      []string{"malicious-activity"},
		})
	}
	return stixBundle{
		Type:    "bundle",
		ID:      "bundle--" + uuidV5(fmt.Sprintf("bundle|%d", len(objs))),
		Objects: objs,
	}
}

// handleAPISTIX: GET /api/stix — STIX 2.1 bundle of indicators.
func (s *Server) handleAPISTIX(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	inds, err := s.store.ListIndicators(store.IndicatorFilter{
		Kind: r.URL.Query().Get("kind"), Limit: limit,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildSTIXBundle(inds))
}
