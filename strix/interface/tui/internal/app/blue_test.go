package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestBlueSetupRoutesPrepareWithoutStandardLaunch(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{SetupMode: true}
	_, cmd := model.submit(`/blue "C:\Owned Fixture\sample.dll"`)
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "setup.blue_prepare" {
		t.Fatalf("command = %s, want setup.blue_prepare", envelope.Type)
	}
	var payload struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Target != `C:\Owned Fixture\sample.dll` {
		t.Fatalf("target = %q", payload.Target)
	}
}

func TestBlueSetupCarriesReviewedRouteAndCase(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{SetupMode: true}
	_, cmd := model.submit(`/blue --case-id owned-case --provider local --model local-audit --endpoint http://127.0.0.1:11434/v1 --pe-audit "C:\RE LAB\pe-audit.exe" "C:\Owned Fixture\sample.dll"`)
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "setup.blue_prepare" {
		t.Fatalf("command = %s", envelope.Type)
	}
	var payload map[string]string
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"case_id": "owned-case", "provider": "local", "model": "local-audit",
		"endpoint": "http://127.0.0.1:11434/v1", "pe_audit": `C:\RE LAB\pe-audit.exe`,
		"target": `C:\Owned Fixture\sample.dll`,
	} {
		if payload[key] != want {
			t.Errorf("%s = %q, want %q", key, payload[key], want)
		}
	}
}

func TestBlueSetupRejectsUnknownOption(t *testing.T) {
	if _, err := parseBlueSetup(`/blue --unsafe C:\owned.exe`); err == nil {
		t.Fatal("unknown Blue option was accepted")
	}
}

func TestBlueRunKeepsOwningTUIOpen(t *testing.T) {
	model := New(nil)
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "running",
		BluePreview: &protocol.BluePreview{},
	}
	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyCtrlC})
	state := updated.(Model)
	if cmd != nil || state.quitting || !strings.Contains(state.errorText, "Wait for completion") {
		t.Fatal("closing the TUI during Blue would leave the run without an owner")
	}
}

func TestBluePreviewWarnsWhenPEHelperIsMissing(t *testing.T) {
	model := New(nil)
	model.snapshot = protocol.Snapshot{
		SetupMode: true,
		BluePreview: &protocol.BluePreview{
			ScopeSHA256:         strings.Repeat("a", 64),
			ManifestSHA256:      strings.Repeat("b", 64),
			BinaryWithoutHelper: true,
		},
	}
	if view := ansi.Strip(model.bluePreviewView(80)); !strings.Contains(view, "binary inspection will be limited") {
		t.Fatal("Blue preview did not warn about missing PE helper")
	}
}

func TestBluePreviewBindsConfirmationToScope(t *testing.T) {
	model, connection := newCommandTestModel(t)
	firstHash := strings.Repeat("a", 64)
	scopeHash := strings.Repeat("b", 64)
	manifestHash := strings.Repeat("c", 64)
	model.snapshot = protocol.Snapshot{
		SetupMode: true,
		BluePreview: &protocol.BluePreview{
			Target:    `C:\Owned Fixture\sample.dll`,
			Manifest:  `C:\runs\blue\manifest.json`,
			FileCount: 1, TotalBytes: 128,
			ScopeSHA256: scopeHash, ManifestSHA256: manifestHash,
			FirstPath: "sample.dll", FirstSHA256: firstHash,
			IncludedFiles: []string{"sample.dll"}, Operations: []string{"static-read", "analysis", "report"},
		},
	}
	view := ansi.Strip(model.bluePreviewView(80))
	for _, want := range []string{scopeHash, manifestHash, firstHash, "sample.dll", "static-read", "no tool network", "RUN cccccccc"} {
		if !strings.Contains(view, want) {
			t.Fatalf("Blue preview omitted %q", want)
		}
	}
	model.width, model.height = 80, 24
	model.resizeViewport()
	screen := ansi.Strip(model.setupView())
	for _, want := range []string{scopeHash, manifestHash, firstHash, "sample.dll", "RUN cccccccc"} {
		if !strings.Contains(screen, want) {
			t.Fatalf("Blue setup screen omitted %q at 80x24", want)
		}
	}
	updated, cmd := model.submit("RUN aaaaaaaa")
	if cmd != nil || !strings.Contains(updated.(Model).setupContent(), "RUN cccccccc") {
		t.Fatal("first-file hash incorrectly confirmed the full scope")
	}
	_, cmd = model.submit("RUN cccccccc")
	if got := commandFromCmd(t, cmd, connection).Type; got != "setup.blue_confirm" {
		t.Fatalf("command = %s, want setup.blue_confirm", got)
	}
}
