package app

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func parseBlueHandoff(input string) (map[string]any, error) {
	words, err := blueWords(input)
	if err != nil {
		return nil, err
	}
	if len(words) > 0 && words[0] == "/handoff" {
		words = words[1:]
	}
	payload := map[string]any{}
	questions := []string{}
	for index := 0; index < len(words); index++ {
		option := words[index]
		if option != "--scope" && option != "--question" && option != "--model" && option != "--endpoint" {
			return nil, fmt.Errorf("unknown handoff option %q", option)
		}
		index++
		if index >= len(words) || strings.TrimSpace(words[index]) == "" || strings.HasPrefix(words[index], "--") {
			return nil, fmt.Errorf("handoff option %q needs a value", option)
		}
		value := words[index]
		if option == "--question" {
			questions = append(questions, value)
			continue
		}
		key := strings.TrimPrefix(option, "--")
		if _, duplicate := payload[key]; duplicate {
			return nil, fmt.Errorf("handoff option %q was repeated", option)
		}
		payload[key] = value
	}
	if payload["scope"] == nil {
		return nil, errors.New("enter --scope with the new Standard investigation boundary")
	}
	payload["questions"] = questions
	return payload, nil
}

func (m Model) updateBlueHandoff(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	handoff := m.snapshot.BlueHandoff
	switch key.String() {
	case "esc":
		stage := m.blueHandoffStage
		m.blueHandoffStage = blueHandoffNone
		m.input.SetValue("")
		if stage == blueHandoffStageConfirm || stage == blueHandoffLaunchConfirm {
			return m, send(m.client, "blue.handoff_close", map[string]any{})
		}
		return m, nil
	case "enter":
		switch m.blueHandoffStage {
		case blueHandoffCommand:
			if m.blueFindingIndex >= len(m.snapshot.BlueFindings) {
				m.errorText = "Select a recorded Blue finding first"
				return m, nil
			}
			payload, err := parseBlueHandoff(strings.TrimSpace(m.input.Value()))
			if err != nil {
				m.errorText = err.Error()
				return m, nil
			}
			payload["finding_id"] = m.snapshot.BlueFindings[m.blueFindingIndex].ID
			m.input.SetValue("")
			m.blueHandoffStage = blueHandoffNone
			return m, send(m.client, "blue.handoff_preview", payload)
		case blueHandoffStageConfirm:
			if handoff == nil || handoff.Status != "pending_stage" {
				return m, nil
			}
			phrase := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			return m, send(m.client, "blue.handoff_stage", map[string]any{"phrase": phrase})
		case blueHandoffLaunchConfirm:
			if handoff == nil || handoff.Status != "staged" || !handoff.LaunchReady {
				return m, nil
			}
			phrase := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			return m, send(m.client, "blue.handoff_launch", map[string]any{"phrase": phrase})
		default:
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(key)
	return m, cmd
}
