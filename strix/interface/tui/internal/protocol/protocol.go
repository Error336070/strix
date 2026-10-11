package protocol

import "encoding/json"

const Version = 3

var Capabilities = []string{
	"state-revisions",
	"collection-deltas",
	"structured-command-errors",
	"agents-collection",
}

type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type Message struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Level string `json:"level"`
}

type Agent struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ParentID     *string `json:"parent_id"`
	Status       string  `json:"status"`
	ErrorMessage string  `json:"error_message"`
}

// Connection is one MCP connection the run may reach, as the backend projects
// it for the sidebar's MCP panel. Non-secret by construction: only the display
// name, how many tools the connection offers, and whether its live session has
// died (its reconnect-retry gave up). "In use" is not carried here; the client
// derives it from the connection-tagged tool-call events in the event stream.
type Connection struct {
	Name      string `json:"name"`
	ToolCount int    `json:"tool_count"`
	Dead      bool   `json:"dead"`
}

type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	AgentID   string         `json:"agent_id"`
	Timestamp string         `json:"timestamp"`
	Version   int            `json:"version"`
	Data      map[string]any `json:"data"`
}

type Hello struct {
	Capabilities []string `json:"capabilities"`
}

type BluePreview struct {
	Target         string         `json:"target"`
	Manifest       string         `json:"manifest"`
	CaseID         string         `json:"case_id"`
	FileCount      int            `json:"file_count"`
	TotalBytes     int64          `json:"total_bytes"`
	ScopeSHA256    string         `json:"scope_sha256"`
	FirstPath      string         `json:"first_path"`
	FirstSHA256    string         `json:"first_sha256"`
	IncludedFiles  []string       `json:"included_files"`
	RemainingFiles int            `json:"remaining_files"`
	Operations     []string       `json:"operations"`
	Sandbox        map[string]any `json:"sandbox"`
	Model          string         `json:"model"`
	Provider       string         `json:"provider"`
	Approval       string         `json:"approval"`
	Endpoint       *string        `json:"endpoint"`
	PeAudit        map[string]any `json:"pe_audit"`
}

type BlueObservation struct {
	Status           string  `json:"status"`
	Mode             string  `json:"mode"`
	Path             string  `json:"path"`
	SHA256           string  `json:"sha256"`
	TimeoutSeconds   float64 `json:"timeout_seconds"`
	PID              *int    `json:"pid"`
	Evidence         string  `json:"evidence"`
	Warning          string  `json:"warning"`
	Phrase           string  `json:"phrase"`
	GrantPhrase      string  `json:"grant_phrase"`
	GrantEligible    bool    `json:"grant_eligible"`
	GrantUsed        int     `json:"grant_used"`
	GrantSecondsUsed float64 `json:"grant_seconds_used"`
	GrantExpiresUTC  string  `json:"grant_expires_utc"`
	Error            string  `json:"error"`
	ResultStatus     string  `json:"result_status"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	ExitCode         *int    `json:"exit_code"`
}

type Snapshot struct {
	SetupMode           bool             `json:"setup_mode"`
	BlueMode            bool             `json:"blue_mode"`
	ScanStarted         bool             `json:"scan_started"`
	ScanState           string           `json:"scan_state"`
	Targets             []string         `json:"targets"`
	TargetCount         int              `json:"target_count"`
	WorkingDir          string           `json:"working_dir"`
	PendingMount        string           `json:"pending_mount"`
	Instruction         string           `json:"instruction"`
	ScanMode            string           `json:"scan_mode"`
	MaxBudgetUSD        *float64         `json:"max_budget_usd"`
	MaxTurns            int              `json:"max_turns"`
	ScopeMode           string           `json:"scope_mode"`
	DiffBase            string           `json:"diff_base"`
	Model               string           `json:"model"`
	CaidoURL            string           `json:"caido_url"`
	Messages            []Message        `json:"messages"`
	Agents              []Agent          `json:"-"`
	Events              []Event          `json:"-"`
	Vulnerabilities     []map[string]any `json:"-"`
	Usage               map[string]any   `json:"usage"`
	Subscription        bool             `json:"subscription"`
	Connections         []Connection     `json:"connections"`
	ViewerStatus        string           `json:"viewer_status"`
	ViewerURL           *string          `json:"viewer_url"`
	Error               *string          `json:"error"`
	BluePreview         *BluePreview     `json:"blue_preview"`
	BlueObservation     *BlueObservation `json:"blue_observation"`
	ProjectionTruncated bool             `json:"projection_truncated"`
}

type StateUpdate struct {
	Revision int      `json:"revision"`
	State    Snapshot `json:"state"`
}

type CollectionBootstrap struct {
	Collection string            `json:"collection"`
	Revision   int               `json:"revision"`
	Cursor     int               `json:"cursor"`
	NextCursor int               `json:"next_cursor"`
	Done       bool              `json:"done"`
	Items      []json.RawMessage `json:"items"`
}

type CollectionOperation struct {
	Op   string          `json:"op"`
	ID   string          `json:"id,omitempty"`
	Item json.RawMessage `json:"item"`
}

type CollectionDelta struct {
	Collection   string                `json:"collection"`
	BaseRevision int                   `json:"base_revision"`
	Revision     int                   `json:"revision"`
	Cursor       int                   `json:"cursor"`
	NextCursor   int                   `json:"next_cursor"`
	Done         bool                  `json:"done"`
	Operations   []CollectionOperation `json:"operations"`
}

type CommandError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type CommandResult struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   *CommandError   `json:"error"`
}
