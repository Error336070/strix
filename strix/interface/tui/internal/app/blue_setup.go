package app

import (
	"errors"
	"fmt"
	"strings"
)

func parseBlueSetup(input string) (map[string]any, error) {
	words, err := blueWords(input)
	if err != nil {
		return nil, err
	}
	if len(words) < 2 || words[0] != "/blue" {
		return nil, errors.New("use /blue [options] PATH")
	}
	fields := map[string]string{
		"--case-id": "case_id",
		"--pe-audit": "pe_audit",
		"--provider": "provider",
		"--model": "model",
		"--endpoint": "endpoint",
		"--approval": "approval",
	}
	payload := map[string]any{}
	for index := 1; index < len(words); index++ {
		word := words[index]
		if strings.HasPrefix(word, "--") {
			key, known := fields[word]
			if !known {
				return nil, fmt.Errorf("unknown Blue option %q", word)
			}
			if _, duplicate := payload[key]; duplicate {
				return nil, fmt.Errorf("Blue option %q was repeated", word)
			}
			index++
			if index >= len(words) || words[index] == "" || strings.HasPrefix(words[index], "--") {
				return nil, fmt.Errorf("Blue option %q needs a value", word)
			}
			payload[key] = words[index]
			continue
		}
		if _, exists := payload["target"]; exists {
			return nil, errors.New("choose one Blue file or directory")
		}
		payload["target"] = word
	}
	if payload["target"] == nil {
		return nil, errors.New("choose a Blue file or directory")
	}
	return payload, nil
}
