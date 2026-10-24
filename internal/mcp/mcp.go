// Package mcp is a thin Model Context Protocol gateway (JSON-RPC 2.0 over
// stdio, one message per line) in front of the Trove HTTP API. It holds no
// rules of its own: every call goes to the server with the agent's token,
// and the server enforces roles and validation. Approve, reject and import
// are deliberately not exposed.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"trove"
	"trove/internal/api"
	"trove/internal/client"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var str = map[string]any{"type": "string"}

// Tools exposed to agents. There is intentionally no approve/reject/import.
var tools = []tool{
	{"trove_search", "Search the knowledge base (case-insensitive fixed string).", schema([]string{"query"}, map[string]any{"query": str})},
	{"trove_read", "Read a file at HEAD, or as seen through one of your drafts.", schema([]string{"path"}, map[string]any{"path": str, "draft": str})},
	{"trove_list", "List files at HEAD, optionally under a folder prefix.", schema(nil, map[string]any{"prefix": str})},
	{"trove_status", "Show HEAD and your open drafts and proposals.", schema(nil, map[string]any{})},
	{"trove_begin", "Open a draft. Only when the user explicitly asked to record or change knowledge.", schema([]string{"topic"}, map[string]any{"topic": str, "scope": map[string]any{"type": "array", "items": str}})},
	{"trove_write", "Write a whole file into your server-side draft.", schema([]string{"draft", "path", "content"}, map[string]any{"draft": str, "path": str, "content": str})},
	{"trove_delete", "Delete a file in your server-side draft.", schema([]string{"draft", "path"}, map[string]any{"draft": str, "path": str})},
	{"trove_submit", "Submit your draft for human approval. Only on the user's instruction, after showing them the changes.", schema([]string{"draft"}, map[string]any{"draft": str})},
	{"trove_rebase", "Rebase one of your stale proposals: it is superseded and a new draft at HEAD is returned. Redo the change in the new draft.", schema([]string{"id"}, map[string]any{"id": str})},
	{"trove_abort", "Withdraw one of your drafts or proposals.", schema([]string{"id"}, map[string]any{"id": str})},
}

// Run serves MCP on in/out until EOF or ctx is cancelled.
func Run(ctx context.Context, c *client.Client, in io.Reader, out io.Writer) error {
	instructions, err := c.Instructions()
	if err != nil || instructions == "" {
		instructions = trove.AgentInstructions
	}
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	send := func(r response) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(r)
	}
	rd := bufio.NewReaderSize(in, 1<<20)
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, tooLong, err := readLine(rd, MaxLine)
		if tooLong {
			send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32600, "message too large"}})
		} else if len(line) > 0 {
			handle(c, instructions, line, send)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// MaxLine bounds one JSON-RPC message (a full draft file plus escaping).
const MaxLine = 8 << 20

// readLine reads up to '\n'. A longer line is consumed and discarded and
// reported with tooLong, so memory use stays bounded.
func readLine(rd *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, e := rd.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(e, bufio.ErrBufferFull) {
			continue
		}
		return line, tooLong, e
	}
}

func handle(c *client.Client, instructions string, line []byte, send func(response)) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	notification := len(req.ID) == 0
	reply := func(result any, rerr *rpcError) {
		if notification {
			return
		}
		send(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := "2024-11-05"
		if p.ProtocolVersion != "" {
			version = p.ProtocolVersion
		}
		reply(map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "trove", "version": trove.Version},
			"instructions":    instructions,
		}, nil)
	case "ping":
		reply(map[string]any{}, nil)
	case "tools/list":
		reply(map[string]any{"tools": tools}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			reply(nil, &rpcError{-32602, "invalid params"})
			return
		}
		text, err := callTool(c, p.Name, p.Arguments)
		if err != nil {
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}, nil)
			return
		}
		reply(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}, nil)
	default:
		if !notification {
			reply(nil, &rpcError{-32601, "method not found"})
		}
	}
}

type args struct {
	Query   string   `json:"query"`
	Path    string   `json:"path"`
	Draft   string   `json:"draft"`
	Prefix  string   `json:"prefix"`
	Topic   string   `json:"topic"`
	Scope   []string `json:"scope"`
	Content *string  `json:"content"`
	ID      string   `json:"id"`
}

func pretty(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

func callTool(c *client.Client, name string, raw json.RawMessage) (string, error) {
	var a args
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "", fmt.Errorf("invalid arguments: %v", err)
		}
	}
	switch name {
	case "trove_search":
		r, err := c.Search(a.Query)
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_read":
		r, err := c.ReadFile(a.Path, a.Draft)
		if err != nil {
			return "", err
		}
		if r.Deleted {
			return "(deleted in draft " + r.Draft + ")", nil
		}
		return r.Content, nil
	case "trove_list":
		r, err := c.Tree(a.Prefix)
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_status":
		r, err := c.Status()
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_begin":
		r, err := c.Begin(api.BeginReq{Topic: a.Topic, Scope: a.Scope})
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_write":
		if a.Content == nil {
			return "", fmt.Errorf("content is required")
		}
		r, err := c.WriteChange(a.Draft, api.ChangeReq{Path: a.Path, Op: "put", Content: *a.Content})
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_delete":
		r, err := c.WriteChange(a.Draft, api.ChangeReq{Path: a.Path, Op: "delete"})
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_submit":
		r, err := c.Submit(a.Draft, nil)
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_rebase":
		r, err := c.Rebase(a.ID)
		if err != nil {
			return "", err
		}
		return pretty(r)
	case "trove_abort":
		r, err := c.Abort(a.ID)
		if err != nil {
			return "", err
		}
		return pretty(r)
	}
	return "", fmt.Errorf("unknown tool %q", name)
}
