package fakeserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// The write endpoints keep Vaultwarden 1.37.5's routes, checks and answers
// (src/api/core/ciphers.rs, folders.rs): they store what clients send,
// so tests can see what a client changed.

const staleMessage = "The client copy of this cipher is out of date. Resync the client and try again."

// payloadFields are the cipher fields a client sends and the server keeps.
var payloadFields = []string{
	"type", "folderId", "organizationId", "favorite", "reprompt", "key", "name", "notes", "fields",
	"passwordHistory", "login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport", "data",
}

func (s *Server) newID() string {
	s.idSeq++
	return fmt.Sprintf("b%07d-0000-4000-8000-%012d", s.idSeq, s.idSeq)
}

func now() string { return iso(time.Now()) }

// bump advances the account revision after a change. The caller holds s.mu.
func (s *Server) bump() { s.revision = time.Now().UTC() }

func (s *Server) findItem(id string) (int, obj) {
	for i, it := range s.items {
		if it["id"] == id {
			return i, it
		}
	}
	return -1, nil
}

func readBody(r *http.Request) obj {
	raw, _ := io.ReadAll(r.Body)
	var v obj
	_ = json.Unmarshal(raw, &v)
	return v
}

func errMessage(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, obj{"message": msg, "errorModel": obj{"message": msg, "object": "error"}, "error": "", "error_description": "", "object": "error"})
}

// toItem builds the stored item from a client's payload, keeping what the
// server owns of prev.
func toItem(p obj, id string, prev obj) obj {
	it := obj{
		"object": "cipherDetails", "id": id, "creationDate": now(), "revisionDate": now(),
		"deletedDate": nil, "archivedDate": nil, "attachments": nil, "organizationUseTotp": true,
		"collectionIds": []any{}, "edit": true, "viewPassword": true, "permissions": obj{"delete": true, "restore": true},
	}
	for _, k := range []string{"login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport", "notes", "key", "fields", "passwordHistory", "folderId", "organizationId"} {
		it[k] = nil
	}
	if prev != nil {
		for _, k := range []string{"creationDate", "deletedDate", "archivedDate", "attachments", "collectionIds", "edit", "viewPassword", "permissions"} {
			it[k] = prev[k]
		}
	}
	for _, k := range payloadFields {
		if v, ok := p[k]; ok {
			it[k] = v
		}
	}
	if it["favorite"] == nil {
		it["favorite"] = false
	}
	if it["reprompt"] == nil {
		it["reprompt"] = 0
	}
	if l, ok := it["login"].(map[string]any); ok {
		l["uri"] = nil
		if uris, ok := l["uris"].([]any); ok && len(uris) > 0 {
			if u, ok := uris[0].(map[string]any); ok {
				l["uri"] = u["uri"]
			}
		}
	}
	return it
}

// checkUser is Vaultwarden's encryptedFor check, answered with HTTP 422.
func checkUser(w http.ResponseWriter, p obj) bool {
	if p["encryptedFor"] != UserID {
		errMessage(w, 422, "Invalid user cipher")
		return false
	}
	return true
}

func (s *Server) attachmentMeta(w http.ResponseWriter, cipherID, attachmentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, it := s.findItem(cipherID)
	if it != nil {
		atts, _ := it["attachments"].([]obj)
		for _, a := range atts {
			if a["id"] == attachmentID {
				meta := obj{}
				for k, v := range a {
					meta[k] = v
				}
				meta["url"] = s.URL() + "/attachments/" + cipherID + "/" + attachmentID + "?token=signed"
				writeJSON(w, 200, meta)
				return
			}
		}
	}
	errMessage(w, 404, "Attachment doesn't exist")
}

// write serves the endpoints that change the vault; false when path is
// none of them.
func (s *Server) write(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if hook := s.config().OnWrite; hook != nil && r.Method != http.MethodGet {
		hook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := r.Method
	n := len(parts)
	switch {
	case m == http.MethodPost && n == 2 && parts[1] == "ciphers":
		p := readBody(r)
		if !checkUser(w, p) {
			return true
		}
		it := toItem(p, s.newID(), nil)
		it["organizationId"] = nil
		s.items = append(s.items, it)
		s.bump()
		writeJSON(w, 200, it)
	case m == http.MethodPost && n == 3 && parts[1] == "ciphers" && parts[2] == "create":
		body := readBody(r)
		p, _ := body["cipher"].(map[string]any)
		if !checkUser(w, p) {
			return true
		}
		it := toItem(p, s.newID(), nil)
		if cols, ok := body["collectionIds"].([]any); ok {
			it["collectionIds"] = cols
		}
		s.items = append(s.items, it)
		s.bump()
		writeJSON(w, 200, it)
	case m == http.MethodPost && n == 3 && parts[1] == "ciphers" && parts[2] == "import":
		body := readBody(r)
		var folderIDs []string
		folders, _ := body["folders"].([]any)
		for _, f := range folders {
			fo, _ := f.(map[string]any)
			// As Vaultwarden does, a folder the user has keeps its ID; any
			// other becomes a new folder.
			if id, _ := fo["id"].(string); slices.ContainsFunc(s.folders, func(f obj) bool { return f["id"] == id }) {
				folderIDs = append(folderIDs, id)
				continue
			}
			id := s.newID()
			s.folders = append(s.folders, obj{"id": id, "name": fo["name"], "revisionDate": now(), "object": "folder"})
			folderIDs = append(folderIDs, id)
		}
		ciphers, _ := body["ciphers"].([]any)
		var created []obj
		for _, c := range ciphers {
			p, _ := c.(map[string]any)
			it := toItem(p, s.newID(), nil)
			it["folderId"] = nil
			s.items = append(s.items, it)
			created = append(created, it)
		}
		rels, _ := body["folderRelationships"].([]any)
		for _, rel := range rels {
			kv, _ := rel.(map[string]any)
			ci, fi := int(asFloat(kv["key"])), int(asFloat(kv["value"]))
			if ci < len(created) && fi < len(folderIDs) {
				created[ci]["folderId"] = folderIDs[fi]
			}
		}
		s.bump()
		w.WriteHeader(200)
	case m == http.MethodPut && n == 3 && parts[1] == "ciphers" && (parts[2] == "archive" || parts[2] == "unarchive"):
		body := readBody(r)
		ids, _ := body["ids"].([]any)
		var done []obj
		for _, id := range ids {
			if _, it := s.findItem(fmt.Sprint(id)); it != nil {
				if parts[2] == "archive" {
					it["archivedDate"] = now()
				} else {
					it["archivedDate"] = nil
				}
				done = append(done, it)
			}
		}
		s.bump()
		writeJSON(w, 200, obj{"data": done, "object": "list", "continuationToken": nil})
	case m == http.MethodPut && n == 3 && parts[1] == "ciphers" && parts[2] == "move":
		body := readBody(r)
		ids, _ := body["ids"].([]any)
		for _, id := range ids {
			if _, it := s.findItem(fmt.Sprint(id)); it != nil {
				it["folderId"] = body["folderId"]
				it["revisionDate"] = now()
			}
		}
		s.moves++
		s.bump()
		w.WriteHeader(200)
	case parts[1] == "ciphers" && n >= 3:
		return s.writeCipher(w, r, parts)
	case parts[1] == "folders":
		return s.writeFolder(w, r, parts)
	default:
		return false
	}
	return true
}

func asFloat(v any) float64 { f, _ := v.(float64); return f }

func (s *Server) writeCipher(w http.ResponseWriter, r *http.Request, parts []string) bool {
	m, n, id := r.Method, len(parts), parts[2]
	i, it := s.findItem(id)
	if it == nil {
		if (m == http.MethodGet && n == 3) || m != http.MethodGet {
			errMessage(w, 400, "Cipher doesn't exist")
			return true
		}
		return false
	}
	writable := it["edit"] != false
	action := ""
	if n >= 4 {
		action = parts[3]
	}
	switch {
	case m == http.MethodGet && n == 3:
		writeJSON(w, 200, it)
	case (m == http.MethodPut || m == http.MethodPost) && n == 3:
		p := readBody(r)
		if !checkUser(w, p) {
			return true
		}
		if !writable {
			errMessage(w, 400, "Cipher is not write accessible")
			return true
		}
		if last, ok := p["lastKnownRevisionDate"].(string); ok && last != "" && newerBy(it["revisionDate"], last) > time.Second {
			errMessage(w, 400, staleMessage)
			return true
		}
		if it["organizationId"] != nil && p["organizationId"] != it["organizationId"] {
			errMessage(w, 400, "Organization mismatch. Please resync the client before updating the cipher")
			return true
		}
		next := toItem(p, id, it)
		next["organizationId"] = it["organizationId"]
		if it["organizationId"] == nil && p["organizationId"] != nil {
			errMessage(w, 400, "Use the share endpoint to move an item to an organization")
			return true
		}
		s.items[i] = next
		s.bump()
		writeJSON(w, 200, next)
	case m == http.MethodPut && action == "delete":
		if !writable {
			errMessage(w, 400, "Cipher can't be deleted by user")
			return true
		}
		it["deletedDate"], it["revisionDate"] = now(), now()
		s.bump()
		w.WriteHeader(200)
	case m == http.MethodPut && action == "restore":
		it["deletedDate"], it["revisionDate"] = nil, now()
		s.bump()
		writeJSON(w, 200, it)
	case m == http.MethodPut && (action == "archive" || action == "unarchive"):
		if action == "archive" {
			it["archivedDate"] = now()
		} else {
			it["archivedDate"] = nil
		}
		s.bump()
		writeJSON(w, 200, it)
	case m == http.MethodDelete && n == 3:
		if !writable {
			errMessage(w, 400, "Cipher can't be deleted by user")
			return true
		}
		s.items = slices.Delete(s.items, i, i+1)
		s.bump()
		w.WriteHeader(200)
	case (m == http.MethodPut || m == http.MethodPost) && action == "collections_v2":
		body := readBody(r)
		cols, _ := body["collectionIds"].([]any)
		it["collectionIds"], it["revisionDate"] = cols, now()
		s.bump()
		writeJSON(w, 200, obj{"object": "optionalCipherDetails", "unavailable": false, "cipher": it})
	case m == http.MethodPost && action == "attachment" && n == 5 && parts[4] == "v2":
		body := readBody(r)
		aid := fmt.Sprintf("att%011d", s.idSeq+1)
		s.idSeq++
		att := obj{"id": aid, "fileName": body["fileName"], "key": body["key"], "size": fmt.Sprint(body["fileSize"]),
			"sizeName": fmt.Sprintf("%v Bytes", body["fileSize"]), "url": s.URL() + "/attachments/" + id + "/" + aid, "object": "attachment"}
		atts, _ := it["attachments"].([]obj)
		it["attachments"] = append(atts, att)
		it["revisionDate"] = now()
		s.bump()
		if s.cfg.AzureUploads {
			writeJSON(w, 200, obj{"attachmentId": aid, "url": s.blobURL(id, aid, s.cfg.AzureURLExpired), "fileUploadType": 1, "cipherResponse": it, "object": "attachment-fileUpload"})
			return true
		}
		writeJSON(w, 200, obj{"attachmentId": aid, "url": "/api/ciphers/" + id + "/attachment/" + aid, "fileUploadType": 0, "cipherResponse": it, "object": "attachment-fileUpload"})
	case m == http.MethodGet && action == "attachment" && n == 6 && parts[5] == "renew":
		s.renewals++
		writeJSON(w, 200, obj{"url": s.blobURL(id, parts[4], false), "fileUploadType": 1, "object": "attachment-fileUpload"})
	case m == http.MethodPost && action == "attachment" && n == 5 && s.cfg.DirectUploadFails:
		errMessage(w, 400, "Upload refused")
	case m == http.MethodPost && action == "attachment" && n == 5:
		file, _, err := r.FormFile("data")
		if err != nil {
			errMessage(w, 400, "No attachment data")
			return true
		}
		data, _ := io.ReadAll(file)
		s.blobs[parts[4]] = data
		w.WriteHeader(200)
	case m == http.MethodDelete && action == "attachment" && n == 5 && s.cfg.AttachmentDeleteFails:
		errMessage(w, 500, "storage unavailable")
	case m == http.MethodDelete && action == "attachment" && n == 5:
		atts, _ := it["attachments"].([]obj)
		it["attachments"] = slices.DeleteFunc(slices.Clone(atts), func(a obj) bool { return a["id"] == parts[4] })
		delete(s.blobs, parts[4])
		it["revisionDate"] = now()
		s.bump()
		writeJSON(w, 200, obj{"cipher": it})
	default:
		return false
	}
	return true
}

// newerBy is how much later stored is than the client's copy, as
// Vaultwarden compares them.
func newerBy(stored any, client string) time.Duration {
	ss, _ := stored.(string)
	ts, errS := time.Parse(time.RFC3339Nano, ss)
	tc, errC := time.Parse(time.RFC3339Nano, client)
	if errS != nil || errC != nil {
		return 0
	}
	return ts.Sub(tc)
}

func (s *Server) writeFolder(w http.ResponseWriter, r *http.Request, parts []string) bool {
	m, n := r.Method, len(parts)
	switch {
	case m == http.MethodPost && n == 2:
		p := readBody(r)
		f := obj{"id": s.newID(), "name": p["name"], "revisionDate": now(), "object": "folder"}
		s.folders = append(s.folders, f)
		s.bump()
		writeJSON(w, 200, f)
	case n == 3:
		i := slices.IndexFunc(s.folders, func(f obj) bool { return f["id"] == parts[2] })
		if i < 0 {
			errMessage(w, 400, "Invalid folder")
			return true
		}
		switch m {
		case http.MethodGet:
			writeJSON(w, 200, s.folders[i])
		case http.MethodPut, http.MethodPost:
			p := readBody(r)
			s.folders[i]["name"], s.folders[i]["revisionDate"] = p["name"], now()
			s.bump()
			writeJSON(w, 200, s.folders[i])
		case http.MethodDelete:
			for _, it := range s.items {
				if it["folderId"] == parts[2] {
					it["folderId"] = nil
				}
			}
			s.folders = slices.Delete(s.folders, i, i+1)
			s.bump()
			w.WriteHeader(200)
		default:
			return false
		}
	default:
		return false
	}
	return true
}

// Items returns the stored items, for tests to inspect.
func (s *Server) Items() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.items)
	var out []map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// Touch changes an item as another client would: a new revision date.
func (s *Server) Touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, it := s.findItem(id); it != nil {
		it["revisionDate"] = now()
		s.bump()
	}
}

// Item returns one stored item, or nil.
func (s *Server) Item(id string) map[string]any {
	for _, it := range s.Items() {
		if it["id"] == id {
			return it
		}
	}
	return nil
}

// Mutate changes a stored item as another client would. org encrypts a
// value with the organization key, personal with the user key.
func (s *Server) Mutate(id string, fn func(it map[string]any, org, personal func(string) any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, it := s.findItem(id); it != nil {
		fn(it, func(v string) any { return enc(v, s.keys.orgKey) }, func(v string) any { return enc(v, s.keys.userKey) })
		it["revisionDate"] = now()
		s.bump()
	}
}

// Clear empties the vault: no items and no folders.
func (s *Server) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items, s.folders = nil, nil
	s.bump()
}

// DropAttachmentData removes the stored bytes of an attachment, so its
// download fails.
func (s *Server) DropAttachmentData(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, id)
}

// blobURL is a signed blob storage URL for an attachment upload.
func (s *Server) blobURL(cipherID, attID string, expired bool) string {
	expiry := time.Now().Add(time.Hour)
	if expired {
		expiry = time.Now().Add(-time.Minute)
	}
	return s.URL() + "/blob/" + cipherID + "/" + attID + "?sv=2024-08-04&se=" + expiry.UTC().Format(time.RFC3339) + "&sr=b&sp=cw&sig=signature"
}

// azureBlob is blob storage: a PUT of a block blob with a valid signature
// stores the attachment, which the server then treats as validated, as
// its storage event handler does.
func (s *Server) azureBlob(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobPuts = append(s.blobPuts, r.Header.Clone())
	parts := strings.Split(strings.Trim(path, "/"), "/")
	q := r.URL.Query()
	expiry, err := time.Parse(time.RFC3339, q.Get("se"))
	switch {
	case r.Method != http.MethodPut || len(parts) != 3:
		w.WriteHeader(405)
	case s.cfg.BlobFails:
		w.WriteHeader(500)
	case q.Get("sig") != "signature" || err != nil || expiry.Before(time.Now()):
		w.WriteHeader(403)
	case r.Header.Get("x-ms-blob-type") != "BlockBlob" || r.Header.Get("x-ms-version") != q.Get("sv") || r.Header.Get("x-ms-date") == "" || r.Header.Get("Authorization") != "":
		w.WriteHeader(400)
	default:
		data, _ := io.ReadAll(r.Body)
		s.blobs[parts[2]] = data
		w.WriteHeader(201)
	}
}

// BlobPuts returns the headers of each blob storage request.
func (s *Server) BlobPuts() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.blobPuts)
}

// Renewals counts upload URL renewals.
func (s *Server) Renewals() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewals
}

// Moves counts PUT /api/ciphers/move requests.
func (s *Server) Moves() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.moves
}
