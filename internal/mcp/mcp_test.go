package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if len(tools) != 12 {
		t.Fatalf("expected the 12 planned tools, got %d", len(tools))
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

func TestProposalTools(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/proposals" {
			w.Write([]byte(`[{"id":"abc","state":"pending","agent":"other","topic":"t","files":[]}]`))
			return
		}
		w.Write([]byte(`{"id":"abc","state":"pending","agent":"other","topic":"t","files":[],"changes":[{"path":"a.md","op":"put","content":"x"}]}`))
	}))
	defer srv.Close()
	c := client.New(srv.URL, "x")

	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
	}
	for _, want := range []string{"trove_proposals", "trove_proposal", "trove_list"} {
		if !strings.Contains(strings.Join(names, " "), want) {
			t.Fatalf("tool %s missing", want)
		}
	}

	out, err := callTool(c, "trove_proposals", json.RawMessage(`{"state":"all","all_agents":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, client.ProposalNotice+"\n\n[") || !strings.Contains(out, `"agent": "other"`) {
		t.Fatalf("output must start with the notice then the JSON: %s", out)
	}
	if _, err := callTool(c, "trove_proposals", nil); err != nil {
		t.Fatal(err)
	}
	out, err = callTool(c, "trove_proposal", json.RawMessage(`{"id":"abc"}`))
	if err != nil || !strings.HasPrefix(out, client.ProposalNotice+"\n\n{") || !strings.Contains(out, "a.md") {
		t.Fatalf("detail output: %v %s", err, out)
	}
	if len(queries) != 3 || !strings.Contains(queries[0], "agents=all") || !strings.Contains(queries[0], "state=all") {
		t.Fatalf("all_agents must send agents=all: %v", queries)
	}
	if strings.Contains(queries[1], "agents=") {
		t.Fatalf("default list must not send agents: %v", queries)
	}
}
