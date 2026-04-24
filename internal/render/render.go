package render

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"mime/multipart"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ContentTypeJSON           = "application/json"
	ContentTypeJSONUTF8       = "application/json; charset=utf-8"
	ContentTypeVendorJSON     = "application/vnd.api+json"
	ContentTypeMergeJSON      = "application/merge-patch+json"
	ContentTypePatchJSON      = "application/json-patch+json"
	ContentTypeProblemJSON    = "application/problem+json"
	ContentTypeLDJSON         = "application/ld+json"
	ContentTypeHALJSON        = "application/hal+json"
	ContentTypeActivityJSON   = "application/activity+json"
	ContentTypeSCIMJSON       = "application/scim+json"
	ContentTypeManifestJSON   = "application/manifest+json"
	ContentTypeReportsJSON    = "application/reports+json"
	ContentTypeCSPReport      = "application/csp-report"
	ContentTypeTextJSON       = "text/json"
	ContentTypeXJSON          = "application/x-json"
	ContentTypeNDJSON         = "application/x-ndjson"
	ContentTypePlain          = "text/plain"
	ContentTypePlainUTF8      = "text/plain; charset=utf-8"
	ContentTypeJavaScript     = "application/javascript"
	ContentTypeTextJavaScript = "text/javascript"

	ContentTypeXML         = "application/xml"
	ContentTypeXMLUTF8     = "application/xml; charset=utf-8"
	ContentTypeTextXML     = "text/xml"
	ContentTypeTextXMLUTF8 = "text/xml; charset=utf-8"
	ContentTypeSOAPXML     = "application/soap+xml"
	ContentTypeAtomXML     = "application/atom+xml"
	ContentTypeRSSXML      = "application/rss+xml"

	ContentTypeForm      = "application/x-www-form-urlencoded"
	ContentTypeFormUTF8  = "application/x-www-form-urlencoded; charset=utf-8"
	ContentTypeMultipart = "multipart/form-data; boundary=ctfuzzboundary9c8b6f17c4a2d5e0"

	ContentTypeYAML      = "application/yaml"
	ContentTypeXYAML     = "application/x-yaml"
	ContentTypeTextYAML  = "text/yaml"
	ContentTypeTextXYAML = "text/x-yaml"

	ContentTypeOctetStream = "application/octet-stream"

	multipartBoundary = "ctfuzzboundary9c8b6f17c4a2d5e0"
)

var CoreContentTypes = []string{
	ContentTypeJSON,
	ContentTypeXML,
	ContentTypeForm,
}

var JSONContentTypes = []string{
	ContentTypeJSON,
	ContentTypeJSONUTF8,
	ContentTypeVendorJSON,
	ContentTypeMergeJSON,
	ContentTypePatchJSON,
	ContentTypeProblemJSON,
	ContentTypeLDJSON,
	ContentTypeHALJSON,
	ContentTypeActivityJSON,
	ContentTypeSCIMJSON,
	ContentTypeManifestJSON,
	ContentTypeReportsJSON,
	ContentTypeCSPReport,
	ContentTypeTextJSON,
	ContentTypeXJSON,
	ContentTypeNDJSON,
	ContentTypePlain,
	ContentTypePlainUTF8,
	ContentTypeJavaScript,
	ContentTypeTextJavaScript,
	ContentTypeOctetStream,
}

var XMLContentTypes = []string{
	ContentTypeXML,
	ContentTypeXMLUTF8,
	ContentTypeTextXML,
	ContentTypeTextXMLUTF8,
	ContentTypeSOAPXML,
	ContentTypeAtomXML,
	ContentTypeRSSXML,
}

var FormContentTypes = []string{
	ContentTypeForm,
	ContentTypeFormUTF8,
	ContentTypeMultipart,
}

var YAMLContentTypes = []string{
	ContentTypeYAML,
	ContentTypeXYAML,
	ContentTypeTextYAML,
	ContentTypeTextXYAML,
}

var AllContentTypes = []string{
	ContentTypeJSON,
	ContentTypeJSONUTF8,
	ContentTypeVendorJSON,
	ContentTypeMergeJSON,
	ContentTypePatchJSON,
	ContentTypeProblemJSON,
	ContentTypeLDJSON,
	ContentTypeHALJSON,
	ContentTypeActivityJSON,
	ContentTypeSCIMJSON,
	ContentTypeManifestJSON,
	ContentTypeReportsJSON,
	ContentTypeCSPReport,
	ContentTypeTextJSON,
	ContentTypeXJSON,
	ContentTypeNDJSON,
	ContentTypePlain,
	ContentTypePlainUTF8,
	ContentTypeJavaScript,
	ContentTypeTextJavaScript,
	ContentTypeOctetStream,
	ContentTypeXML,
	ContentTypeXMLUTF8,
	ContentTypeTextXML,
	ContentTypeTextXMLUTF8,
	ContentTypeSOAPXML,
	ContentTypeAtomXML,
	ContentTypeRSSXML,
	ContentTypeForm,
	ContentTypeFormUTF8,
	ContentTypeMultipart,
	ContentTypeYAML,
	ContentTypeXYAML,
	ContentTypeTextYAML,
	ContentTypeTextXYAML,
}

const TypeHelp = "all,core,json,xml,form,json-family,xml-family,form-family,yaml-family,text, or exact supported content types"

type rendererKind int

const (
	renderJSON rendererKind = iota
	renderXML
	renderForm
	renderMultipart
	renderYAML
	renderNDJSON
)

func ResolveTypes(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return append([]string(nil), AllContentTypes...), nil
	}

	groups := map[string][]string{
		"all":         AllContentTypes,
		"broad":       AllContentTypes,
		"core":        CoreContentTypes,
		"legacy":      CoreContentTypes,
		"json":        {ContentTypeJSON},
		"xml":         {ContentTypeXML},
		"form":        {ContentTypeForm},
		"urlencoded":  {ContentTypeForm},
		"multipart":   {ContentTypeMultipart},
		"yaml":        {ContentTypeYAML},
		"jsons":       JSONContentTypes,
		"json-family": JSONContentTypes,
		"xmls":        XMLContentTypes,
		"xml-family":  XMLContentTypes,
		"forms":       FormContentTypes,
		"form-family": FormContentTypes,
		"yamls":       YAMLContentTypes,
		"yaml-family": YAMLContentTypes,
		"text":        {ContentTypePlain, ContentTypeTextJSON, ContentTypeTextXML, ContentTypeTextYAML},
	}

	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.ToLower(strings.TrimSpace(part))
		if item == "" {
			return nil, errors.New("--types contains an empty item")
		}

		var add []string
		if group, ok := groups[item]; ok {
			add = group
		} else {
			canonical, err := CanonicalType(item)
			if err != nil {
				return nil, err
			}
			add = []string{canonical}
		}

		for _, contentType := range add {
			if _, exists := seen[contentType]; exists {
				continue
			}
			seen[contentType] = struct{}{}
			out = append(out, contentType)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--types must include at least one content type")
	}
	return out, nil
}

func CanonicalType(raw string) (string, error) {
	contentType := strings.ToLower(strings.TrimSpace(raw))
	switch contentType {
	case "multipart/form-data":
		return ContentTypeMultipart, nil
	case "application/x-www-form-urlencoded":
		return ContentTypeForm, nil
	case "application/x-www-form-urlencoded; charset=utf8":
		return ContentTypeFormUTF8, nil
	}
	if _, err := rendererFor(contentType); err != nil {
		return "", err
	}
	return contentType, nil
}

func Body(contentType string, payload map[string]any) ([]byte, error) {
	kind, err := rendererFor(contentType)
	if err != nil {
		return nil, err
	}

	switch kind {
	case renderJSON:
		return JSON(payload)
	case renderNDJSON:
		return NDJSON(payload)
	case renderXML:
		return XML(payload, "root")
	case renderForm:
		return Form(payload)
	case renderMultipart:
		return Multipart(payload)
	case renderYAML:
		return YAML(payload)
	default:
		return nil, fmt.Errorf("unsupported content type %q", contentType)
	}
}

func ShortName(contentType string) string {
	switch contentType {
	case ContentTypeJSON:
		return "json"
	case ContentTypeJSONUTF8:
		return "json-utf8"
	case ContentTypeVendorJSON:
		return "vnd-json"
	case ContentTypeMergeJSON:
		return "merge-json"
	case ContentTypePatchJSON:
		return "patch-json"
	case ContentTypeProblemJSON:
		return "problem-json"
	case ContentTypeLDJSON:
		return "ld-json"
	case ContentTypeHALJSON:
		return "hal-json"
	case ContentTypeActivityJSON:
		return "activity-json"
	case ContentTypeSCIMJSON:
		return "scim-json"
	case ContentTypeManifestJSON:
		return "manifest-json"
	case ContentTypeReportsJSON:
		return "reports-json"
	case ContentTypeCSPReport:
		return "csp-report"
	case ContentTypeTextJSON:
		return "text-json"
	case ContentTypeXJSON:
		return "x-json"
	case ContentTypeNDJSON:
		return "ndjson"
	case ContentTypePlain:
		return "plain-json"
	case ContentTypePlainUTF8:
		return "plain-json-utf8"
	case ContentTypeJavaScript:
		return "js-json"
	case ContentTypeTextJavaScript:
		return "text-js-json"
	case ContentTypeOctetStream:
		return "octet-json"
	case ContentTypeXML:
		return "xml"
	case ContentTypeXMLUTF8:
		return "xml-utf8"
	case ContentTypeTextXML:
		return "text-xml"
	case ContentTypeTextXMLUTF8:
		return "text-xml-utf8"
	case ContentTypeSOAPXML:
		return "soap-xml"
	case ContentTypeAtomXML:
		return "atom-xml"
	case ContentTypeRSSXML:
		return "rss-xml"
	case ContentTypeForm:
		return "form"
	case ContentTypeFormUTF8:
		return "form-utf8"
	case ContentTypeMultipart:
		return "multipart"
	case ContentTypeYAML:
		return "yaml"
	case ContentTypeXYAML:
		return "x-yaml"
	case ContentTypeTextYAML:
		return "text-yaml"
	case ContentTypeTextXYAML:
		return "text-x-yaml"
	default:
		return mediaType(contentType)
	}
}

func JSON(payload map[string]any) ([]byte, error) {
	return json.Marshal(payload)
}

func NDJSON(payload map[string]any) ([]byte, error) {
	body, err := JSON(payload)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func XML(payload map[string]any, root string) ([]byte, error) {
	if !ValidXMLName(root) {
		return nil, errors.New("invalid XML root name")
	}

	var out bytes.Buffer
	if err := writeXMLElement(&out, root, payload); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func Form(payload map[string]any) ([]byte, error) {
	values := url.Values{}
	if err := flattenForm(values, "", payload); err != nil {
		return nil, err
	}
	return []byte(values.Encode()), nil
}

func Multipart(payload map[string]any) ([]byte, error) {
	pairs, err := flattenPairs("", payload)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	w := multipart.NewWriter(&out)
	if err := w.SetBoundary(multipartBoundary); err != nil {
		return nil, err
	}
	for _, p := range pairs {
		if strings.Contains(p.key, multipartBoundary) || strings.Contains(p.value, multipartBoundary) {
			return nil, errors.New("multipart boundary appears in rendered payload")
		}
		if err := w.WriteField(p.key, p.value); err != nil {
			_ = w.Close()
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func YAML(payload map[string]any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeYAMLMap(&out, payload, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func ValidXMLName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	if strings.Contains(name, ":") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(name), "xml") {
		return false
	}

	for i, r := range name {
		if i == 0 {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' {
				continue
			}
			return false
		}
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '_' ||
			r == '-' ||
			r == '.' {
			continue
		}
		return false
	}
	return true
}

func writeXMLElement(out *bytes.Buffer, name string, value any) error {
	if !ValidXMLName(name) {
		return fmt.Errorf("invalid XML element name %q", name)
	}

	out.WriteByte('<')
	out.WriteString(name)
	out.WriteByte('>')

	switch v := value.(type) {
	case map[string]any:
		keys := sortedKeys(v)
		for _, key := range keys {
			if err := writeXMLElement(out, key, v[key]); err != nil {
				return err
			}
		}
	default:
		if err := xml.EscapeText(out, []byte(scalarString(v))); err != nil {
			return err
		}
	}

	out.WriteString("</")
	out.WriteString(name)
	out.WriteByte('>')
	return nil
}

func flattenForm(values url.Values, prefix string, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := sortedKeys(v)
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			if err := flattenForm(values, name, v[key]); err != nil {
				return err
			}
		}
	default:
		if prefix == "" {
			return errors.New("form payload root must be an object")
		}
		values.Set(prefix, scalarString(v))
	}
	return nil
}

type pair struct {
	key   string
	value string
}

func flattenPairs(prefix string, value any) ([]pair, error) {
	switch v := value.(type) {
	case map[string]any:
		keys := sortedKeys(v)
		out := make([]pair, 0, len(keys))
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			children, err := flattenPairs(name, v[key])
			if err != nil {
				return nil, err
			}
			out = append(out, children...)
		}
		return out, nil
	default:
		if prefix == "" {
			return nil, errors.New("payload root must be an object")
		}
		return []pair{{key: prefix, value: scalarString(v)}}, nil
	}
}

func writeYAMLMap(out *bytes.Buffer, value map[string]any, indent int) error {
	keys := sortedKeys(value)
	for _, key := range keys {
		writeIndent(out, indent)
		out.WriteString(key)
		switch v := value[key].(type) {
		case map[string]any:
			out.WriteString(":\n")
			if err := writeYAMLMap(out, v, indent+2); err != nil {
				return err
			}
		default:
			out.WriteString(": ")
			encoded, err := yamlScalar(v)
			if err != nil {
				return err
			}
			out.WriteString(encoded)
			out.WriteByte('\n')
		}
	}
	return nil
}

func writeIndent(out *bytes.Buffer, indent int) {
	for i := 0; i < indent; i++ {
		out.WriteByte(' ')
	}
}

func yamlScalar(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		return "null", nil
	case string:
		data, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(data), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case json.Number:
		return v.String(), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	default:
		data, err := json.Marshal(scalarString(v))
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func scalarString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func rendererFor(contentType string) (rendererKind, error) {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if contentType == "" {
		return renderJSON, errors.New("content type must not be empty")
	}
	if contentType == ContentTypeMultipart {
		return renderMultipart, nil
	}

	base := mediaType(contentType)
	switch {
	case base == "application/x-ndjson" || base == "application/ndjson":
		return renderNDJSON, nil
	case base == "application/json" ||
		base == "application/csp-report" ||
		base == "text/json" ||
		base == "application/x-json" ||
		base == "application/javascript" ||
		base == "text/javascript" ||
		base == "application/x-javascript" ||
		base == "text/plain" ||
		base == "application/octet-stream" ||
		strings.HasSuffix(base, "+json"):
		return renderJSON, nil
	case base == "application/xml" ||
		base == "text/xml" ||
		strings.HasSuffix(base, "+xml"):
		return renderXML, nil
	case base == "application/x-www-form-urlencoded":
		return renderForm, nil
	case base == "application/yaml" ||
		base == "application/x-yaml" ||
		base == "text/yaml" ||
		base == "text/x-yaml" ||
		strings.HasSuffix(base, "+yaml"):
		return renderYAML, nil
	default:
		return renderJSON, fmt.Errorf("unsupported content type %q", contentType)
	}
}

func mediaType(contentType string) string {
	base, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(base)
}
