// Package evaluation scores device observations against independently supplied
// labels. It performs no network requests, catalog lookup or identity inference.
package evaluation

const (
	Schema        = 1
	ReportedModel = "reported_model"
	RetailModel   = "retail_model"
	Family        = "family"
	Kind          = "kind"
)

// Label lists aliases for one independently verified fact, not competing models.
type Label struct {
	Accepted   []string `json:"accepted"`
	SourceKind string   `json:"source_kind"`
	Source     string   `json:"source"`
}
type Case struct {
	ID     string           `json:"id"`
	Class  string           `json:"class"`
	States []string         `json:"states"`
	Truth  map[string]Label `json:"truth"`
}
type Truth struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Kind   string `json:"kind"` // physical or synthetic
	Cases  []Case `json:"cases"`
}

// Observation maps one output record to an independently assigned case ID.
// All seen records for a case are combined by set union before scoring.
type Observation struct {
	ID          string              `json:"id"`
	CaseID      string              `json:"case_id"`
	Addresses   []string            `json:"addresses,omitempty"`
	Seen        bool                `json:"seen"`
	Responsive  bool                `json:"responsive"`
	Predictions map[string][]string `json:"predictions,omitempty"`
}
type Run struct {
	Schema       int           `json:"schema"`
	ID           string        `json:"id"`
	Dataset      string        `json:"dataset"`
	System       string        `json:"system"`
	Version      string        `json:"version"`
	Context      string        `json:"context"`
	Source       string        `json:"source"`
	DurationMS   *int64        `json:"duration_ms,omitempty"`
	Incomplete   bool          `json:"incomplete"`
	Warnings     []string      `json:"warnings,omitempty"`
	Observations []Observation `json:"observations"`
	Unmapped     []string      `json:"unmapped,omitempty"`
}

// Bindings explicitly associate exact scoped addresses with physical case IDs.
// The adapter never joins addresses using names, MACs, or recognition output.
type Bindings struct {
	Schema    int               `json:"schema"`
	Dataset   string            `json:"dataset"`
	RunID     string            `json:"run_id"`
	Version   string            `json:"version"`
	Context   string            `json:"context"`
	Source    string            `json:"source"`
	Addresses map[string]string `json:"addresses"`
}
type FieldScore struct {
	Labeled   int      `json:"labeled"`
	Correct   int      `json:"correct"`
	Incorrect int      `json:"incorrect"`
	Ambiguous int      `json:"ambiguous"`
	Unknown   int      `json:"unknown"`
	Missed    int      `json:"missed"`
	Unlabeled int      `json:"unlabeled"`
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
}
type Group struct {
	Cases            int                   `json:"cases"`
	Observed         int                   `json:"observed"`
	Responsive       int                   `json:"responsive"`
	Records          int                   `json:"records"`
	Fragmentation    int                   `json:"fragmentation"`
	ObservedRecall   *float64              `json:"observed_recall"`
	ResponsiveRecall *float64              `json:"responsive_recall"`
	Fields           map[string]FieldScore `json:"fields"`
}
type CaseResult struct {
	ID          string              `json:"id"`
	Observed    bool                `json:"observed"`
	Responsive  bool                `json:"responsive"`
	Records     int                 `json:"records"`
	Predictions map[string][]string `json:"predictions"`
	Outcomes    map[string]string   `json:"outcomes"`
}
type Result struct {
	Schema      int              `json:"schema"`
	Dataset     string           `json:"dataset"`
	DatasetKind string           `json:"dataset_kind"`
	RunID       string           `json:"run_id"`
	System      string           `json:"system"`
	Version     string           `json:"version"`
	Context     string           `json:"context"`
	Source      string           `json:"source"`
	DurationMS  *int64           `json:"duration_ms,omitempty"`
	Incomplete  bool             `json:"incomplete"`
	Warnings    []string         `json:"warnings,omitempty"`
	Unmapped    []string         `json:"unmapped,omitempty"`
	Overall     Group            `json:"overall"`
	ByClass     map[string]Group `json:"by_class"`
	ByState     map[string]Group `json:"by_state"`
	Cases       []CaseResult     `json:"cases"`
}
