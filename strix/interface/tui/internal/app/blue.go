package app

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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
		render.Col(amber).Render("Type RUN " + preview.ScopeSHA256[:min(8, len(preview.ScopeSHA256))] + " to start"),
		render.Dim().Render("Target: ") + render.Col(white).Render(truncatePath(preview.Target, inner-8)),
		render.Dim().Render(fmt.Sprintf("%d files · %d bytes · case %s", preview.FileCount, preview.TotalBytes, preview.CaseID)),
		render.Dim().Render("Operations: ") + render.Col(white).Render(strings.Join(preview.Operations, ", ")),
		render.Dim().Render("Sandbox: read only · no tool network"),
	}
	rows = append(rows, blueHashRows("Scope SHA-256 (all manifest entries)", preview.ScopeSHA256, inner)...)
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
	observation := m.snapshot.BlueObservation
	if observation == nil {
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
