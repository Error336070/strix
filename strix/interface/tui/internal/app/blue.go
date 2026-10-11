package app

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

func blueHashRows(label, hash string, width int) []string {
	rows := []string{render.Dim().Render(label)}
	chunk := max(8, width-4)
	for len(hash) > 0 {
		end := min(chunk, len(hash))
		rows = append(rows, "  "+render.Col(white).Render(hash[:end]))
		hash = hash[end:]
	}
	return rows
}

func blueEvidenceLink(path string) string {
	normalized := strings.ReplaceAll(path, "\\", "/")
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	uri := (&url.URL{Scheme: "file", Path: normalized}).String()
	return ansi.SetHyperlink(uri) + render.Col(lightBlue).Render("open evidence") + ansi.ResetHyperlink()
}

// The scope digest covers every path, size, and SHA-256 entry in manifest.json.
// Showing it beside the first file's full hash makes the RUN phrase reviewable
// even when a directory is too large to list in the setup column.
func (m Model) bluePreviewView(width int) string {
	preview := m.snapshot.BluePreview
	if preview == nil {
		return ""
	}
	inner := max(12, width-4)
	rows := []string{
		render.Bold(lightBlue).Render("Blue scope preview"),
		render.Col(amber).Render("Type RUN " + preview.ManifestSHA256[:min(8, len(preview.ManifestSHA256))] + " to start"),
		render.Dim().Render("Target: ") + render.Col(white).Render(truncatePath(preview.Target, inner-8)),
		render.Dim().Render(fmt.Sprintf("%d files · %d bytes · case %s", preview.FileCount, preview.TotalBytes, preview.CaseID)),
		render.Dim().Render("Route: ") + render.Col(white).Render(truncatePath(preview.Provider+" / "+preview.Model+" · approval "+preview.Approval, inner-7)),
		render.Dim().Render("Operations: ") + render.Col(white).Render(strings.Join(preview.Operations, ", ")),
		render.Dim().Render("Sandbox: read only · no tool network"),
	}
	if preview.Endpoint != nil {
		rows = append(rows, render.Dim().Render("Local endpoint: ")+render.Col(white).Render(truncatePath(*preview.Endpoint, inner-16)))
	}
	if toolPath, ok := preview.PeAudit["path"].(string); ok {
		rows = append(rows, render.Dim().Render("PE helper: ")+render.Col(white).Render(truncatePath(toolPath, inner-11)))
		rows = append(rows, render.Col(amber).Render("PE helper is executable code; review its path and hash."))
		if toolHash, ok := preview.PeAudit["sha256"].(string); ok {
			rows = append(rows, blueHashRows("PE helper SHA-256", toolHash, inner)...)
		}
	}
	if preview.BinaryWithoutHelper {
		rows = append(rows, render.Col(amber).Render("PE files present without a pinned helper; binary inspection will be limited."))
	}
	rows = append(rows, blueHashRows("Scope SHA-256 (all manifest entries)", preview.ScopeSHA256, inner)...)
	rows = append(rows, blueHashRows("Review SHA-256 (manifest and settings)", preview.ManifestSHA256, inner)...)
	rows = append(rows, render.Dim().Render("Included files:"))
	visible := min(len(preview.IncludedFiles), max(2, m.height-22))
	for _, path := range preview.IncludedFiles[:visible] {
		rows = append(rows, "  "+render.Col(white).Render(truncatePath(path, inner-2)))
	}
	if hidden := preview.FileCount - visible; hidden > 0 {
		rows = append(rows, render.Dim().Render(fmt.Sprintf("  +%d more in manifest.json", hidden)))
	}
	rows = append(rows, render.Dim().Render("First file: ")+render.Col(white).Render(truncatePath(preview.FirstPath, inner-12)))
	rows = append(rows, blueHashRows("First file SHA-256", preview.FirstSHA256, inner)...)
	rows = append(rows,
		render.Dim().Render("Manifest: ")+render.Col(white).Render(truncatePath(preview.Manifest, inner-10)),
	)
	return "  " + strings.Join(rows, "\n  ")
}

func (m Model) blueRunView() string {
	preview := m.snapshot.BluePreview
	if preview == nil {
		return ""
	}
	width := min(max(24, m.width-4), 76)
	inner := max(16, width-8)
	rows := []string{
		render.Bold(lightBlue).Render("Strix Blue"),
		render.Col(white).Render("Status: " + m.snapshot.ScanState),
	}
	handoffActive := m.snapshot.BlueHandoff != nil &&
		m.snapshot.BlueHandoff.Status != "launched" && m.snapshot.BlueHandoff.Status != "stage_failed"
	if m.snapshot.ScanState == "completed" && !handoffActive {
		if count := len(m.snapshot.BlueFindings); count > 0 {
			index := min(m.blueFindingIndex, count-1)
			finding := m.snapshot.BlueFindings[index]
			rows = append(rows,
				render.Col(white).Render(fmt.Sprintf("Finding %d/%d: %s [%s] %s", index+1, count, finding.ID, finding.Severity, truncate(finding.Title, inner-25))),
				render.Dim().Render("j/k select finding · h investigate in Standard"),
			)
		} else {
			rows = append(rows, render.Dim().Render("No structured Blue findings recorded for handoff"))
		}
	}
	observation := m.snapshot.BlueObservation
	if handoffActive {
		// The handoff review has its own target, hashes, and scope. Keep it in view
		// on a standard terminal instead of duplicating the run summary here.
	} else if observation == nil {
		rows = append(rows,
			render.Dim().Render(fmt.Sprintf("%d files · %d bytes", preview.FileCount, preview.TotalBytes)),
			render.Col(white).Render(truncatePath(preview.Target, inner)),
			render.Dim().Render("Blue evidence: ")+render.Col(white).Render(truncatePath(preview.Manifest, inner-15)),
		)
	} else {
		mode := observation.Mode
		if observation.PID != nil {
			mode += fmt.Sprintf(" · PID %d", *observation.PID)
		}
		rows = append(rows,
			render.Bold(amber).Render("Runtime observation: "+observation.Status),
			render.Col(white).Render(fmt.Sprintf("%s · %.1f seconds", mode, observation.TimeoutSeconds)),
			render.Dim().Render("Target: ")+render.Col(white).Render(ansi.Wrap(observation.Path, inner, "")),
		)
		rows = append(rows, blueHashRows("Target path SHA-256", observation.SHA256, inner)...)
		if observation.GrantPhrase != "" || observation.GrantEligible {
			rows = append(rows, blueHashRows("Grant scope SHA-256 (manifest snapshot)", preview.ScopeSHA256, inner)...)
		}
		rows = append(rows,
			render.Dim().Render("Evidence: ")+blueEvidenceLink(observation.Evidence),
			render.Col(white).Render(ansi.Wrap(observation.Evidence, inner, "")),
		)
		switch observation.Status {
		case "pending":
			rows = append(rows,
				render.Col(red).Render(ansi.Wrap(observation.Warning, inner, " ")),
				render.Col(amber).Render("Type "+observation.Phrase+" to approve this one action"),
				render.Dim().Render("Esc cancels without starting the process"),
			)
			if observation.GrantPhrase != "" {
				rows = append(rows,
					render.Col(amber).Render("Or type "+observation.GrantPhrase+" to start this action and grant"),
					render.Col(white).Render("up to 3 launch actions for this exact run and executable"),
					render.Dim().Render("30 total observation seconds · expires "+observation.GrantExpiresUTC),
					render.Dim().Render("Every later /observe action requires its own preview and Enter"),
				)
			} else if observation.GrantEligible {
				rows = append(rows,
					render.Col(amber).Render("Press Enter to run this preview under the scoped grant"),
					render.Dim().Render(fmt.Sprintf("Grant used %d/3 actions · %.1f/30 seconds", observation.GrantUsed, observation.GrantSecondsUsed)),
					render.Dim().Render("Expires "+observation.GrantExpiresUTC),
				)
			}
		case "running":
			rows = append(rows, render.Dim().Render("Observation is active. Evidence is written to the path above."))
		case "completed":
			rows = append(rows, render.Col(green).Render(fmt.Sprintf("Result: %s · %.1f seconds", observation.ResultStatus, observation.ElapsedSeconds)))
		case "failed":
			rows = append(rows, render.Col(red).Render(ansi.Wrap(observation.Error, inner, " ")))
		}
	}
	if m.snapshot.Error != nil {
		rows = append(rows, render.Col(red).Render(truncate(*m.snapshot.Error, width-4)))
	}
	if handoff := m.snapshot.BlueHandoff; handoff != nil {
		rows = append(rows, render.Bold(lightBlue).Render("Investigate in Standard: "+handoff.Status))
		switch handoff.Status {
		case "pending_stage":
			rows = append(rows,
				render.Col(white).Render(truncate(handoff.FindingID+" · "+handoff.FindingTitle, inner)),
				render.Dim().Render("Scope: ")+render.Col(white).Render(truncate(handoff.Scope, inner-7)),
				render.Dim().Render("Route: ")+render.Col(white).Render(handoffRoute(handoff)),
				render.Dim().Render("Snapshot: ")+render.Col(white).Render(truncatePath(handoff.Snapshot, inner-10)),
			)
			for _, question := range handoff.Questions {
				rows = append(rows, render.Dim().Render("Question: ")+render.Col(white).Render(ansi.Wrap(question, inner-10, " ")))
			}
			rows = append(rows, blueHashRows("Source file SHA-256", handoff.SourceSHA256, inner)...)
			rows = append(rows, blueHashRows("Finding evidence SHA-256", handoff.FindingSHA256, inner)...)
			rows = append(rows, blueHashRows("Review SHA-256 (scope and route)", handoff.ReviewSHA256, inner)...)
			rows = append(rows,
				render.Col(amber).Render("Type "+handoff.Phrase+" to stage a target copy"),
				render.Dim().Render("Esc cancels without staging or launching Standard"),
			)
		case "staging", "launching":
			rows = append(rows, render.Dim().Render("Waiting for the reviewed handoff action to finish"))
		case "staged":
			rows = append(rows,
				render.Col(white).Render(truncate(handoff.FindingID+" · "+handoff.FindingTitle, inner)),
				render.Dim().Render("Scope: ")+render.Col(white).Render(truncate(handoff.Scope, inner-7)),
				render.Dim().Render("Staged target: ")+render.Col(white).Render(truncatePath(handoff.StagedTarget, inner-15)),
			)
			for _, question := range handoff.Questions {
				rows = append(rows, render.Dim().Render("Question: ")+render.Col(white).Render(ansi.Wrap(question, inner-10, " ")))
			}
			rows = append(rows, blueHashRows("Staged record SHA-256", handoff.RecordSHA256, inner)...)
			if handoff.LaunchReady {
				rows = append(rows,
					render.Col(white).Render("Local Standard route: "+handoffRoute(handoff)),
					render.Col(amber).Render("Type "+handoff.Phrase+" to launch Standard in a new console"),
					render.Dim().Render("Esc keeps the staged copy without launching"),
				)
			} else {
				rows = append(rows, render.Col(amber).Render("Staged only. Configure a local Standard model and endpoint before launch."))
			}
		case "launched":
			if handoff.StandardPID != nil {
				rows = append(rows, render.Col(green).Render(fmt.Sprintf("Standard started in a new console · PID %d", *handoff.StandardPID)))
			}
		case "stage_failed":
			rows = append(rows, render.Col(red).Render(truncate(handoff.Error, inner)))
		}
	}
	if m.errorText != "" {
		rows = append(rows, render.Col(amber).Render(truncate(m.errorText, width-4)))
	}
	if m.blueActionStage == blueActionCommand {
		rows = append(rows,
			render.Dim().Render("Enter /observe launch \"file.exe\" [seconds]"),
			render.Dim().Render("or /observe attach \"file.exe\" PID [seconds]"),
			m.input.View(),
		)
	} else if m.blueActionStage == blueActionConfirm {
		rows = append(rows, m.input.View())
	} else if m.blueHandoffStage == blueHandoffCommand {
		rows = append(rows,
			render.Dim().Render("/handoff --scope \"NEW SCOPE\" [--question \"QUESTION\"]"),
			render.Dim().Render("Optional: --model openai/MODEL --endpoint http://127.0.0.1:PORT/v1"),
			m.input.View(),
		)
	} else if m.blueHandoffStage == blueHandoffStageConfirm || m.blueHandoffStage == blueHandoffLaunchConfirm {
		rows = append(rows, m.input.View())
	} else if m.snapshot.ScanState == "completed" && (observation == nil || observation.Status == "completed" || observation.Status == "failed") {
		rows = append(rows, render.Dim().Render("Press o to prepare one runtime observation"))
	}
	if m.snapshot.ScanState == "running" || m.snapshot.ScanState == "preparing" || (observation != nil && observation.Status == "running") {
		rows = append(rows, render.Dim().Render("Blue is running. Keep the TUI open until it finishes."))
	} else {
		rows = append(rows, render.Dim().Render("Ctrl+C to close the TUI"))
	}
	content := lipgloss.NewStyle().Width(width).Padding(1, 2).
		Border(lipgloss.RoundedBorder()).BorderForeground(lightBlue).
		Render(strings.Join(rows, "\n"))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

func handoffRoute(handoff *protocol.BlueHandoff) string {
	if handoff.Model == nil || handoff.Endpoint == nil {
		return "stage only (no local Standard endpoint)"
	}
	return *handoff.Model + " · " + *handoff.Endpoint
}
