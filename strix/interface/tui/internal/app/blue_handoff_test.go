package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestBlueHandoffCommandSelectsFindingAndScopesRoute(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "completed",
		BluePreview:  &protocol.BluePreview{},
		BlueFindings: []protocol.BlueFinding{{ID: "F-1"}, {ID: "F-2", Title: "Selected"}},
	}
	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model = updated.(Model)
	if cmd != nil || model.blueFindingIndex != 1 {
		t.Fatal("j did not select the next Blue finding")
	}
	updated, cmd = model.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	model = updated.(Model)
	if cmd != nil || model.blueHandoffStage != blueHandoffCommand {
		t.Fatal("h did not open the selected finding handoff prompt")
	}
	model.input.SetValue(`/handoff --scope "Review owned source" --question "Is the finding reproducible?" --model openai/local --endpoint http://127.0.0.1:11434/v1`)
	_, cmd = model.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "blue.handoff_preview" {
		t.Fatalf("sent %s instead of a read-only preview", envelope.Type)
	}
	var payload struct {
		FindingID string   `json:"finding_id"`
		Scope     string   `json:"scope"`
		Questions []string `json:"questions"`
		Model     string   `json:"model"`
		Endpoint  string   `json:"endpoint"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.FindingID != "F-2" || payload.Scope != "Review owned source" ||
		payload.Model != "openai/local" || payload.Endpoint != "http://127.0.0.1:11434/v1" ||
		len(payload.Questions) != 1 {
		t.Fatalf("wrong scoped handoff preview: %+v", payload)
	}
}

func TestBlueHandoffParserRejectsMalformedScopeAndRoute(t *testing.T) {
	for _, input := range []string{
		`--model openai/local`, `--scope ""`, `--scope Review --scope Repeat`,
		`--scope Review --unknown value`, `--scope "unfinished`,
	} {
		if _, err := parseBlueHandoff(input); err == nil {
			t.Fatalf("accepted malformed handoff %q", input)
		}
	}
}

func TestBlueHandoffRequiresTwoDistinctConfirmations(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "completed",
		BluePreview: &protocol.BluePreview{},
		BlueHandoff: &protocol.BlueHandoff{
			Status: "pending_stage", Phrase: "STAGE abcdef12",
			FindingID: "F-1", FindingTitle: "Owned finding", Scope: "Review source",
			Questions: []string{"Is the finding reproducible?"},
			SourceSHA256: strings.Repeat("a", 64), FindingSHA256: strings.Repeat("b", 64),
			FindingsSHA256: strings.Repeat("c", 64), ReviewSHA256: strings.Repeat("d", 64),
		},
	}
	model.width, model.height = 80, 24
	model.blueHandoffStage = blueHandoffStageConfirm
	view := ansi.Strip(model.blueRunView())
	if lines := strings.Count(view, "\n") + 1; lines > model.height {
		t.Fatalf("handoff preview uses %d lines in a %d-line terminal", lines, model.height)
	}
	for _, want := range []string{"F-1", "Review source", "Is the finding reproducible?", strings.Repeat("a", 64), strings.Repeat("d", 64), "STAGE abcdef12"} {
		if !strings.Contains(view, want) {
			t.Fatalf("handoff preview omitted %q", want)
		}
	}
	model.input.SetValue("STAGE abcdef12")
	_, cmd := model.updateBlue(tea.KeyMsg{Type: tea.KeyEnter})
	if got := commandFromCmd(t, cmd, connection); got.Type != "blue.handoff_stage" {
		t.Fatalf("sent %s instead of staging", got.Type)
	}
	model, connection = newCommandTestModel(t)
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "completed",
		BluePreview: &protocol.BluePreview{},
		BlueHandoff: &protocol.BlueHandoff{
			Status: "staged", Phrase: "STANDARD 98765432", LaunchReady: true,
			FindingID: "F-1", FindingTitle: "Owned finding", Scope: "Review source",
			Questions: []string{"Is the finding reproducible?"},
			StagePath: `C:\runs\handoffs\h1`, StagedTarget: `C:\runs\handoffs\h1\target`,
			RecordSHA256: strings.Repeat("e", 64),
		},
	}
	model.width, model.height = 100, 30
	model.blueHandoffStage = blueHandoffLaunchConfirm
	stagedView := ansi.Strip(model.blueRunView())
	for _, want := range []string{"Owned finding", "Review source", "Is the finding reproducible?", `C:\runs\handoffs\h1\target`} {
		if !strings.Contains(stagedView, want) {
			t.Fatalf("launch review omitted %q", want)
		}
	}
	model.input.SetValue("STANDARD 98765432")
	_, cmd = model.updateBlue(tea.KeyMsg{Type: tea.KeyEnter})
	if got := commandFromCmd(t, cmd, connection); got.Type != "blue.handoff_launch" {
		t.Fatalf("sent %s instead of second launch approval", got.Type)
	}
}

func TestBlueHandoffWithoutEndpointShowsStageOnly(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 28
	model.snapshot = protocol.Snapshot{
		SetupMode: false, ScanStarted: true, ScanState: "completed",
		BluePreview: &protocol.BluePreview{},
		BlueHandoff: &protocol.BlueHandoff{
			Status: "staged", LaunchReady: false,
			StagedTarget: `C:\runs\handoffs\h1\target`,
			RecordSHA256: strings.Repeat("a", 64),
		},
	}
	view := ansi.Strip(model.blueRunView())
	if !strings.Contains(view, "Staged only") || strings.Contains(view, "Type STANDARD") {
		t.Fatal("stage-only handoff displayed a Standard launch instruction")
	}
}
