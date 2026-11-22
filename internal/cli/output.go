package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// obj is a JSON object that keeps its key order, as the JavaScript objects
// bw prints do. A nil value prints null; absent keys are simply not added.
type obj []kv

type kv struct {
	k string
	v any
}

func (o obj) set(k string, v any) obj { return append(o, kv{k, v}) }

// opt adds k only when v is not empty, as bw omits undefined fields.
func (o obj) opt(k string, v string) obj {
	if v == "" {
		return o
	}
	return append(o, kv{k, v})
}

func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := marshal(e.k)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		v, err := marshal(e.v)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshal encodes like JSON.stringify: no HTML escaping.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// jsTime formats t as Date.prototype.toJSON does.
func jsTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func jsTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return jsTime(*t)
}

// response is bw's Response: a success with data, or an error.
type response struct {
	success bool
	message string
	data    any // an obj, a list, or a raw []any of IDs for multiple results
	// raw is the data of a message response that --raw prints.
}

type message struct {
	title   string
	text    *string
	raw     *string
	noColor bool
}

type listData []any

type stringData struct{ value *string }

type templateData struct{ template any }

// fileWritten marks a response whose output already went to stdout.
type fileWritten struct{}

func success(data any) response { return response{success: true, data: data} }

func failure(msg string) response { return response{message: msg} }

func failureData(msg string, data any) response { return response{message: msg, data: data} }

func notFound() response { return failure("Not found.") }

func multipleResults(ids []string) response {
	var b strings.Builder
	b.WriteString("More than one result was found. Try getting a specific object by `id` instead. The following objects were found:")
	data := make([]any, len(ids))
	for i, id := range ids {
		b.WriteString("\n" + id)
		data[i] = id
	}
	return failureData(b.String(), data)
}

func str(s string) response { return success(stringData{value: &s}) }

func msg(title string) response { return success(message{title: title}) }

func ptr(s string) *string { return &s }

// envelope is the --response form of r.
func (r response) envelope() obj {
	o := obj{}.set("success", r.success)
	if !r.success {
		o = o.set("message", r.message)
		if r.data != nil {
			o = o.set("data", r.data)
		}
		return o
	}
	if d := dataJSON(r.data); d != nil {
		o = o.set("data", d)
	}
	return o
}

// dataJSON is the JSON form of a success payload, as bw's response classes
// serialize.
func dataJSON(d any) any {
	switch d := d.(type) {
	case nil, fileWritten:
		return nil
	case listData:
		return obj{}.set("object", "list").set("data", []any(d))
	case stringData:
		return obj{}.set("object", "string").set("data", nullable(d.value))
	case templateData:
		return obj{}.set("object", "template").set("template", d.template)
	case message:
		o := obj{}.set("noColor", d.noColor).set("object", "message").set("title", d.title).set("message", nullable(d.text))
		if d.raw != nil {
			o = o.set("raw", *d.raw)
		}
		return o
	}
	return d
}

func nullable(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
