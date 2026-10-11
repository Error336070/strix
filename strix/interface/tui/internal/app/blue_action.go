package app

import (
	"errors"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Blue action commands use quotes for paths with spaces. Backslashes are
// literal, so an ordinary Windows path does not need shell escaping.
func blueWords(input string) ([]string, error) {
	var words []string
	var current strings.Builder
	quoted, started := false, false
	for _, char := range input {
		switch {
		case char == '"':
			quoted, started = !quoted, true
		case (char == ' ' || char == '\t') && !quoted:
			if started {
				words = append(words, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(char)
			started = true
		}
	}
	if quoted {
		return nil, errors.New("close the quoted path before submitting")
	}
	if started {
		words = append(words, current.String())
	}
	return words, nil
}

func parseBlueAction(input string) (map[string]any, error) {
	words, err := blueWords(input)
	if err != nil {
		return nil, err
	}
	if len(words) > 0 && words[0] == "/observe" {
		words = words[1:]
	}
	if len(words) < 2 {
		return nil, errors.New("use launch PATH [seconds] or attach PATH PID [seconds]")
	}
	mode, path := words[0], words[1]
	if path == "" {
		return nil, errors.New("choose an included .exe path")
	}
	payload := map[string]any{"mode": mode, "path": path, "timeout_seconds": 5.0}
	switch mode {
	case "launch":
		if len(words) > 3 {
			return nil, errors.New("use launch PATH [seconds]")
		}
		if len(words) == 3 {
			seconds, err := strconv.ParseFloat(words[2], 64)
			if err != nil {
				return nil, errors.New("seconds must be a number")
			}
			payload["timeout_seconds"] = seconds
		}
	case "attach":
		if len(words) < 3 || len(words) > 4 {
			return nil, errors.New("use attach PATH PID [seconds]")
		}
		pid, err := strconv.Atoi(words[2])
		if err != nil || pid <= 0 {
			return nil, errors.New("PID must be a positive integer")
		}
		payload["pid"] = pid
		if len(words) == 4 {
			seconds, err := strconv.ParseFloat(words[3], 64)
			if err != nil {
				return nil, errors.New("seconds must be a number")
			}
			payload["timeout_seconds"] = seconds
		}
	default:
		return nil, errors.New("choose launch or attach")
	}
	return payload, nil
}

func (m Model) updateBlue(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	observation := m.snapshot.BlueObservation
	active := observation != nil && observation.Status == "running"
	switch key.String() {
	case "ctrl+c", "ctrl+q":
		if m.snapshot.ScanState == "running" || m.snapshot.ScanState == "preparing" || active {
			m.errorText = "Blue is active. Wait for completion before closing the TUI."
			return m, nil
		}
		m.quitting = true
		return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
	case "esc":
		if m.blueActionStage == blueActionConfirm && observation != nil && observation.Status == "pending" {
			m.blueActionStage = blueActionNone
			m.input.SetValue("")
			return m, send(m.client, "blue.observe_cancel", map[string]any{})
		}
		m.blueActionStage = blueActionNone
		m.input.SetValue("")
		return m, nil
	case "o":
		if m.snapshot.ScanState == "completed" && !active && m.blueActionStage == blueActionNone && (observation == nil || observation.Status != "pending") {
			m.blueActionStage = blueActionCommand
			m.input.SetValue("")
			m.input.Focus()
			m.errorText = ""
			return m, nil
		}
	case "enter":
		if m.blueActionStage == blueActionCommand {
			value := strings.TrimSpace(m.input.Value())
			payload, err := parseBlueAction(value)
			if err != nil {
				m.errorText = err.Error()
				return m, nil
			}
			m.input.SetValue("")
			m.blueActionStage = blueActionNone
			return m, send(m.client, "blue.observe_preview", payload)
		}
		if m.blueActionStage == blueActionConfirm && observation != nil && observation.Status == "pending" {
			phrase := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			return m, send(m.client, "blue.observe_confirm", map[string]any{"phrase": phrase})
		}
	}
	if m.blueActionStage == blueActionCommand || m.blueActionStage == blueActionConfirm {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(key)
		return m, cmd
	}
	return m, nil
}
