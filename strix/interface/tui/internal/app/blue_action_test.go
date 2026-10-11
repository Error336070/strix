package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestBlueActionParserKeepsWindowsPathsAndExplicitMode(t *testing.T) {
	request, err := parseBlueAction(`/observe launch "bin\Owned App.exe" 3`)
	if err != nil {
		t.Fatal(err)
	}
	if request["mode"] != "launch" || request["path"] != `bin\Owned App.exe` || request["timeout_seconds"] != 3.0 {
		t.Fatalf("wrong launch request: %#v", request)
	}
	attach, err := parseBlueAction(`attach "bin\Owned App.exe" 4321 2`)
	if err != nil || attach["pid"] != 4321 || attach["mode"] != "attach" {
		t.Fatalf("wrong attach request: %#v, %v", attach, err)
	}
	for _, bad := range []string{`launch "unfinished`, "attach owned.exe", "launch owned.exe 0 bad", "run owned.exe"} {
		if _, err := parseBlueAction(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestBlueActionPromptSendsPreviewThenTargetBoundConfirmation(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{SetupMode: false, ScanStarted: true, ScanState: "completed", BluePreview: &protocol.BluePreview{}}
	updated, cmd := model.updateBlue(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	model = updated.(Model)
	if cmd != nil || model.blueActionStage != blueActionCommand {
		t.Fatal("o did not open the runtime command prompt")
	}
	model.input.SetValue(`launch "owned.exe" 3`)
	updated, cmd = model.updateBlue(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "blue.observe_preview" {
		t.Fatalf("sent %s instead of preview", envelope.Type)
	}
	var request struct {
		Mode string `json:"mode"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(envelope.Payload, &request); err != nil {
		t.Fatal(err)
	}
	if request.Mode != "launch" || request.Path != "owned.exe" {
		t.Fatalf("wrong request: %#v", request)
	}
	model.snapshot.BlueObservation = &protocol.BlueObservation{
		Status: "pending", Mode: "launch", Path: `C:\runs\blue\inputs\owned.exe`,
		SHA256: strings.Repeat("a", 64), TimeoutSeconds: 3,
		Evidence: `C:\runs\blue\runtime-launch.jsonl`,
		Warning:  "This PE may change this Windows host. This observation does not isolate the target.",
		Phrase:   "LAUNCH 1234567890ABCDEF1234",
	}
	model.blueActionStage = blueActionConfirm
	model.width, model.height = 80, 24
	view := ansi.Strip(model.blueRunView())
	for _, want := range []string{"launch", "3.0 seconds", strings.Repeat("a", 64), "isolate", "LAUNCH 1234567890ABCDEF1234"} {
		if !strings.Contains(view, want) {
			t.Fatalf("runtime preview omitted %q", want)
		}
	}
	if !strings.Contains(model.blueRunView(), ansi.SetHyperlink("file:///C:/runs/blue/runtime-launch.jsonl")) {
		t.Fatal("runtime evidence does not have a local file link")
	}
	model.input.SetValue("LAUNCH 1234567890ABCDEF1234")
	connection.Reset()
	_, cmd = model.updateBlue(tea.KeyMsg{Type: tea.KeyEnter})
	if got := commandFromCmd(t, cmd, connection); got.Type != "blue.observe_confirm" {
		t.Fatalf("sent %s instead of confirmation", got.Type)
	}
}

func TestBlueActionBlocksQuitWhileObservationRuns(t *testing.T) {
	model := New(nil)
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "completed",
		BluePreview:     &protocol.BluePreview{},
		BlueObservation: &protocol.BlueObservation{Status: "running"},
	}
	updated, cmd := model.updateBlue(tea.KeyMsg{Type: tea.KeyCtrlC})
	state := updated.(Model)
	if cmd != nil || state.quitting || !strings.Contains(state.errorText, "Wait for completion") {
		t.Fatal("observation could lose its owning TUI")
	}
}
