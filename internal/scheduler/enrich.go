package scheduler

import (
	"time"

	"openticollect/internal/ioc"
	"openticollect/internal/models"
	"openticollect/internal/risk"
)

// enrichStore is the slice of the store the enrichment pass needs. It keeps
// enrichFindings unit-testable with a real *store.Store.
type enrichStore interface {
	InsertIndicators(findingID int64, inds []ioc.Indicator) error
	SetFindingRisk(id int64, score int) error
}

// enrichFindings extracts IOCs and leaked credentials from each finding,
// persists the indicators, and stores a deterministic risk score. It is
// best-effort: a per-finding failure is skipped, never fatal to a run.
func enrichFindings(st enrichStore, findings []models.Finding) []error {
	now := time.Now()
	var errs []error
	for _, f := range findings {
		text := f.Excerpt + "\n" + f.Raw
		inds := ioc.Extract(text)
		creds := ioc.ExtractCredentials(text)
		// Credential service domains are useful indicators in their own right.
		for _, svc := range ioc.CredentialServices(creds) {
			inds = append(inds, ioc.Indicator{Kind: ioc.KindDomain, Value: svc})
		}
		if len(inds) > 0 {
			if err := st.InsertIndicators(f.ID, inds); err != nil {
				errs = append(errs, err)
			}
		}
		score := risk.Score(risk.Signals{
			Finding: f, Indicators: inds, Credentials: len(creds), Now: now,
		})
		if err := st.SetFindingRisk(f.ID, score); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
