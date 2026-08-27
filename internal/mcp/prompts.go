package server

import (
	"context"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerPrompts wires the three diagnostic workflows from design.md §4.5.
// These are message templates, not executable workflows — MCP prompts hand
// the model a starting instruction; the model still makes the actual tool
// and resource calls, each independently policy-checked as always.
// Prompts aren't gated by Granted() the way tools/resources are: a prompt
// that references an ungranted capability just produces instructions whose
// tool calls will come back denied, same as the model asking on its own.
func registerPrompts(s *gosdk.Server) {
	s.AddPrompt(&gosdk.Prompt{
		Name:        "diagnose_device",
		Description: "Read a device's relevant registers, cross-reference the fault table, and summarize its condition.",
		Arguments: []*gosdk.PromptArgument{
			{Name: "device", Description: "device name from fieldlink://devices", Required: true},
			{Name: "symptom", Description: "optional description of the observed problem"},
		},
	}, func(ctx context.Context, req *gosdk.GetPromptRequest) (*gosdk.GetPromptResult, error) {
		device := req.Params.Arguments["device"]
		symptom := req.Params.Arguments["symptom"]
		text := fmt.Sprintf(
			"Diagnose device %q using FieldLink. Read fieldlink://devices/%s/registers to "+
				"learn its symbolic register names, then use read_modbus to read the "+
				"registers relevant to its current condition. Cross-reference any fault "+
				"code against fieldlink://devices/%s/faults. Summarize the device's "+
				"condition in plain language for a process engineer.",
			device, device, device)
		if symptom != "" {
			text += fmt.Sprintf(" The reported symptom is: %s.", symptom)
		}
		return &gosdk.GetPromptResult{
			Description: "Diagnose a device",
			Messages: []*gosdk.PromptMessage{
				{Role: "user", Content: &gosdk.TextContent{Text: text}},
			},
		}, nil
	})

	s.AddPrompt(&gosdk.Prompt{
		Name:        "explain_fault_code",
		Description: "Look up a fault code for a device and explain it in plain language.",
		Arguments: []*gosdk.PromptArgument{
			{Name: "device", Description: "device name from fieldlink://devices", Required: true},
			{Name: "code", Description: "the fault code to explain", Required: true},
		},
	}, func(ctx context.Context, req *gosdk.GetPromptRequest) (*gosdk.GetPromptResult, error) {
		device := req.Params.Arguments["device"]
		code := req.Params.Arguments["code"]
		text := fmt.Sprintf(
			"Look up fault code %s for device %q in fieldlink://devices/%s/faults. "+
				"Explain what it means in plain language for a process engineer, and "+
				"list the most likely causes. If the code is not in the table, say so "+
				"plainly rather than guessing.",
			code, device, device)
		return &gosdk.GetPromptResult{
			Description: "Explain a fault code",
			Messages: []*gosdk.PromptMessage{
				{Role: "user", Content: &gosdk.TextContent{Text: text}},
			},
		}, nil
	})

	s.AddPrompt(&gosdk.Prompt{
		Name:        "daily_line_summary",
		Description: "Summarize a device's readings since a given time, flagging anything outside its expected range.",
		Arguments: []*gosdk.PromptArgument{
			{Name: "device", Description: "device name from fieldlink://devices", Required: true},
			{Name: "since", Description: "start time for the summary, e.g. an ISO 8601 timestamp or \"today\"", Required: true},
		},
	}, func(ctx context.Context, req *gosdk.GetPromptRequest) (*gosdk.GetPromptResult, error) {
		device := req.Params.Arguments["device"]
		since := req.Params.Arguments["since"]
		text := fmt.Sprintf(
			"Summarize device %q since %s. Read fieldlink://devices/%s/registers to see "+
				"each register's expected range, then use read_modbus to read its current "+
				"values. Note anything with quality \"out_of_range\" or any nonzero fault "+
				"code explicitly. This is a snapshot, not a historian query — say so if "+
				"asked about values over the full time window rather than implying a "+
				"trend you didn't actually observe.",
			device, since, device)
		return &gosdk.GetPromptResult{
			Description: "Daily line summary",
			Messages: []*gosdk.PromptMessage{
				{Role: "user", Content: &gosdk.TextContent{Text: text}},
			},
		}, nil
	})
}
