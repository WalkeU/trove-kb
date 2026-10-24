package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trove/internal/client"
)

func TestNoApprovalTools(t *testing.T) {
	for _, tl := range tools {
		for _, banned := range []string{"approve", "reject", "import", "review"} {
			if strings.Contains(tl.Name, banned) {
				t.Fatalf("tool %s must not be exposed over MCP", tl.Name)
			}
		}
	}
	if len(tools) != 10 {
		t.Fatalf("expected the 10 planned tools, got %d", len(tools))
	}
}

func TestProtocolBasics(t *testing.T) {
	// The client points nowhere; initialize falls back to the embedded instructions.
	c := client.New("http://192.0.2.1:9", "x")
	c.HTTP.Timeout = 1
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"trove_approve","arguments":{}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"nope"}` + "\n")
	var out bytes.Buffer
	if err := Run(context.Background(), c, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 responses (notification gets none), got %d: %s", len(lines), out.String())
	}
	var r struct {
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct{ Code int } `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil || !r.Result.IsError {
		t.Fatalf("unknown tool must be an error result: %s", lines[1])
	}
	r.Error = nil
	if err := json.Unmarshal([]byte(lines[2]), &r); err != nil || r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("unknown method must be -32601: %s", lines[2])
	}
}
