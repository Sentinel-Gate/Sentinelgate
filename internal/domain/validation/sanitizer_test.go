package validation

import (
	"strings"
	"testing"
)

func TestSanitizer_ValidToolName(t *testing.T) {
	s := NewSanitizer()

	validNames := []string{
		"my_tool",
		"MyTool",
		"tool-name",
		"a",
		"A",
		"readFile",
		"read_file",
		"read-file",
		"Tool123",
		"tool_with_numbers_123",
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			err := s.ValidateToolName(name)
			if err != nil {
				t.Errorf("ValidateToolName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestSanitizer_EmptyToolName(t *testing.T) {
	s := NewSanitizer()

	err := s.ValidateToolName("")
	if err == nil {
		t.Fatal("ValidateToolName(\"\") = nil, want error")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error is not *ValidationError: %T", err)
	}

	if valErr.Code != ErrCodeInvalidParams {
		t.Errorf("Code = %d, want %d", valErr.Code, ErrCodeInvalidParams)
	}
	if valErr.Message != "tool name is required" {
		t.Errorf("Message = %q, want %q", valErr.Message, "tool name is required")
	}
}

func TestSanitizer_TooLongToolName(t *testing.T) {
	s := NewSanitizer()

	// Create a 256-character name (over the 255 limit)
	longName := "a" + strings.Repeat("b", 255)
	if len(longName) != 256 {
		t.Fatalf("longName length = %d, want 256", len(longName))
	}

	err := s.ValidateToolName(longName)
	if err == nil {
		t.Fatal("ValidateToolName(longName) = nil, want error")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error is not *ValidationError: %T", err)
	}

	if valErr.Code != ErrCodeInvalidParams {
		t.Errorf("Code = %d, want %d", valErr.Code, ErrCodeInvalidParams)
	}
	if valErr.Message != "tool name too long" {
		t.Errorf("Message = %q, want %q", valErr.Message, "tool name too long")
	}
}

func TestSanitizer_InvalidToolNameFormat(t *testing.T) {
	s := NewSanitizer()

	invalidNames := []struct {
		name    string
		pattern string
	}{
		{"123tool", "starts with number"},
		{"tool.name", "contains dot"},
		{"tool name", "contains space"},
		{"_tool", "starts with underscore"},
		{"-tool", "starts with hyphen"},
		{"tool@name", "contains at sign"},
		{"tool#name", "contains hash"},
	}

	for _, tc := range invalidNames {
		t.Run(tc.pattern, func(t *testing.T) {
			err := s.ValidateToolName(tc.name)
			if err == nil {
				t.Fatalf("ValidateToolName(%q) = nil, want error", tc.name)
			}

			valErr, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error is not *ValidationError: %T", err)
			}

			if valErr.Code != ErrCodeInvalidParams {
				t.Errorf("Code = %d, want %d", valErr.Code, ErrCodeInvalidParams)
			}
		})
	}
}

func TestSanitizer_PathTraversalInToolName(t *testing.T) {
	s := NewSanitizer()

	pathTraversalNames := []string{
		"../etc/passwd",
		"tool/../other",
		"..tool",
		"tool/..",
		"/etc/passwd",
		"tool/other",
	}

	for _, name := range pathTraversalNames {
		t.Run(name, func(t *testing.T) {
			err := s.ValidateToolName(name)
			if err == nil {
				t.Fatalf("ValidateToolName(%q) = nil, want error", name)
			}

			valErr, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error is not *ValidationError: %T", err)
			}

			if valErr.Code != ErrCodeInvalidParams {
				t.Errorf("Code = %d, want %d", valErr.Code, ErrCodeInvalidParams)
			}
			if valErr.Message != "invalid characters in tool name" {
				t.Errorf("Message = %q, want %q", valErr.Message, "invalid characters in tool name")
			}
		})
	}
}

func TestSanitizer_RemovesNullBytes(t *testing.T) {
	s := NewSanitizer()

	input := "hello\x00world"
	result, err := s.SanitizeValue(input)
	if err != nil {
		t.Fatalf("SanitizeValue(%q) error = %v", input, err)
	}

	str, ok := result.(string)
	if !ok {
		t.Fatalf("result is not string: %T", result)
	}

	expected := "helloworld"
	if str != expected {
		t.Errorf("SanitizeValue(%q) = %q, want %q", input, str, expected)
	}
}

func TestSanitizer_TruncatesLongString(t *testing.T) {
	s := NewSanitizer()

	// Create a 2MB string (double the limit)
	input := strings.Repeat("a", 2*MaxStringLength)
	if len(input) != 2*MaxStringLength {
		t.Fatalf("input length = %d, want %d", len(input), 2*MaxStringLength)
	}

	result, err := s.SanitizeValue(input)
	if err != nil {
		t.Fatalf("SanitizeValue(longString) error = %v", err)
	}

	str, ok := result.(string)
	if !ok {
		t.Fatalf("result is not string: %T", result)
	}

	if len(str) != MaxStringLength {
		t.Errorf("len(result) = %d, want %d", len(str), MaxStringLength)
	}
}

func TestSanitizer_PreservesShortString(t *testing.T) {
	s := NewSanitizer()

	input := "hello"
	result, err := s.SanitizeValue(input)
	if err != nil {
		t.Fatalf("SanitizeValue(%q) error = %v", input, err)
	}

	str, ok := result.(string)
	if !ok {
		t.Fatalf("result is not string: %T", result)
	}

	if str != input {
		t.Errorf("SanitizeValue(%q) = %q, want %q", input, str, input)
	}
}

func TestSanitizer_SanitizesNestedMap(t *testing.T) {
	s := NewSanitizer()

	input := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": "hello\x00world",
			"nested": map[string]interface{}{
				"level3": "foo\x00bar",
			},
		},
		"top": "top\x00value",
	}

	result, err := s.SanitizeValue(input)
	if err != nil {
		t.Fatalf("SanitizeValue(nested) error = %v", err)
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not map: %T", result)
	}

	// Check top-level value
	top, ok := m["top"].(string)
	if !ok || top != "topvalue" {
		t.Errorf("m[\"top\"] = %v, want %q", m["top"], "topvalue")
	}

	// Check level 2 value
	level1, ok := m["level1"].(map[string]interface{})
	if !ok {
		t.Fatalf("m[\"level1\"] is not map: %T", m["level1"])
	}
	level2, ok := level1["level2"].(string)
	if !ok || level2 != "helloworld" {
		t.Errorf("level1[\"level2\"] = %v, want %q", level1["level2"], "helloworld")
	}

	// Check level 3 value
	nested, ok := level1["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("level1[\"nested\"] is not map: %T", level1["nested"])
	}
	level3, ok := nested["level3"].(string)
	if !ok || level3 != "foobar" {
		t.Errorf("nested[\"level3\"] = %v, want %q", nested["level3"], "foobar")
	}
}

func TestSanitizer_SanitizesArray(t *testing.T) {
	s := NewSanitizer()

	input := []interface{}{
		"hello\x00world",
		"foo\x00bar",
		[]interface{}{
			"nested\x00array",
		},
	}

	result, err := s.SanitizeValue(input)
	if err != nil {
		t.Fatalf("SanitizeValue(array) error = %v", err)
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("result is not []interface{}: %T", result)
	}

	if len(arr) != 3 {
		t.Fatalf("len(arr) = %d, want 3", len(arr))
	}

	expected := []string{"helloworld", "foobar"}
	for i, exp := range expected {
		s, ok := arr[i].(string)
		if !ok || s != exp {
			t.Errorf("arr[%d] = %v, want %q", i, arr[i], exp)
		}
	}

	// Check nested array
	nestedArr, ok := arr[2].([]interface{})
	if !ok {
		t.Fatalf("arr[2] is not []interface{}: %T", arr[2])
	}
	nestedStr, ok := nestedArr[0].(string)
	if !ok || nestedStr != "nestedarray" {
		t.Errorf("nestedArr[0] = %v, want %q", nestedArr[0], "nestedarray")
	}
}

func TestSanitizer_PreservesNonStrings(t *testing.T) {
	s := NewSanitizer()

	testCases := []struct {
		name  string
		input interface{}
	}{
		{"integer", 42},
		{"float", 3.14},
		{"boolean_true", true},
		{"boolean_false", false},
		{"nil", nil},
		{"negative", -100},
		{"float64", float64(123.456)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := s.SanitizeValue(tc.input)
			if err != nil {
				t.Fatalf("SanitizeValue(%v) error = %v", tc.input, err)
			}

			if result != tc.input {
				t.Errorf("SanitizeValue(%v) = %v, want %v", tc.input, result, tc.input)
			}
		})
	}
}

func TestSanitizer_SanitizeToolCall_Valid(t *testing.T) {
	s := NewSanitizer()

	params := map[string]interface{}{
		"name": "readFile",
		"arguments": map[string]interface{}{
			"path": "/some/path",
		},
	}

	result, err := s.SanitizeToolCall(params)
	if err != nil {
		t.Fatalf("SanitizeToolCall error = %v", err)
	}

	name, ok := result["name"].(string)
	if !ok || name != "readFile" {
		t.Errorf("result[\"name\"] = %v, want %q", result["name"], "readFile")
	}

	args, ok := result["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("result[\"arguments\"] is not map: %T", result["arguments"])
	}

	path, ok := args["path"].(string)
	if !ok || path != "/some/path" {
		t.Errorf("args[\"path\"] = %v, want %q", args["path"], "/some/path")
	}
}

func TestSanitizer_SanitizeToolCall_InvalidName(t *testing.T) {
	s := NewSanitizer()

	testCases := []struct {
		name   string
		params map[string]interface{}
	}{
		{
			"missing name",
			map[string]interface{}{
				"arguments": map[string]interface{}{},
			},
		},
		{
			"empty name",
			map[string]interface{}{
				"name":      "",
				"arguments": map[string]interface{}{},
			},
		},
		{
			"invalid name format",
			map[string]interface{}{
				"name":      "123tool",
				"arguments": map[string]interface{}{},
			},
		},
		{
			"path traversal",
			map[string]interface{}{
				"name":      "../etc/passwd",
				"arguments": map[string]interface{}{},
			},
		},
		{
			"name is not string",
			map[string]interface{}{
				"name":      123,
				"arguments": map[string]interface{}{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.SanitizeToolCall(tc.params)
			if err == nil {
				t.Fatal("SanitizeToolCall() = nil error, want error")
			}

			valErr, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("error is not *ValidationError: %T", err)
			}

			if valErr.Code != ErrCodeInvalidParams {
				t.Errorf("Code = %d, want %d", valErr.Code, ErrCodeInvalidParams)
			}
		})
	}
}

func TestSanitizer_SanitizeToolCall_SanitizesArguments(t *testing.T) {
	s := NewSanitizer()

	params := map[string]interface{}{
		"name": "readFile",
		"arguments": map[string]interface{}{
			"path": "/some/path\x00injected",
			"nested": map[string]interface{}{
				"value": "foo\x00bar",
			},
			"array": []interface{}{
				"item\x00one",
				"item\x00two",
			},
		},
		"_meta": map[string]interface{}{
			"apiKey": "test-key",
		},
	}

	result, err := s.SanitizeToolCall(params)
	if err != nil {
		t.Fatalf("SanitizeToolCall error = %v", err)
	}

	args, ok := result["arguments"].(map[string]interface{})
	if !ok {
		t.Fatalf("result[\"arguments\"] is not map: %T", result["arguments"])
	}

	// Check top-level argument
	path, ok := args["path"].(string)
	if !ok || path != "/some/pathinjected" {
		t.Errorf("args[\"path\"] = %v, want %q", args["path"], "/some/pathinjected")
	}

	// Check nested argument
	nested, ok := args["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("args[\"nested\"] is not map: %T", args["nested"])
	}
	value, ok := nested["value"].(string)
	if !ok || value != "foobar" {
		t.Errorf("nested[\"value\"] = %v, want %q", nested["value"], "foobar")
	}

	// Check array argument
	arr, ok := args["array"].([]interface{})
	if !ok {
		t.Fatalf("args[\"array\"] is not []interface{}: %T", args["array"])
	}
	item1, ok := arr[0].(string)
	if !ok || item1 != "itemone" {
		t.Errorf("arr[0] = %v, want %q", arr[0], "itemone")
	}
	item2, ok := arr[1].(string)
	if !ok || item2 != "itemtwo" {
		t.Errorf("arr[1] = %v, want %q", arr[1], "itemtwo")
	}

	// Check _meta is preserved (not sanitized)
	meta, ok := result["_meta"].(map[string]interface{})
	if !ok {
		t.Fatalf("result[\"_meta\"] is not map: %T", result["_meta"])
	}
	apiKey, ok := meta["apiKey"].(string)
	if !ok || apiKey != "test-key" {
		t.Errorf("meta[\"apiKey\"] = %v, want %q", meta["apiKey"], "test-key")
	}
}

func TestSanitizer_SanitizeToolCall_NoArguments(t *testing.T) {
	s := NewSanitizer()

	params := map[string]interface{}{
		"name": "simpleTool",
	}

	result, err := s.SanitizeToolCall(params)
	if err != nil {
		t.Fatalf("SanitizeToolCall error = %v", err)
	}

	name, ok := result["name"].(string)
	if !ok || name != "simpleTool" {
		t.Errorf("result[\"name\"] = %v, want %q", result["name"], "simpleTool")
	}

	// arguments should not exist
	if _, exists := result["arguments"]; exists {
		t.Error("result[\"arguments\"] should not exist for tool with no arguments")
	}
}

func TestSanitizer_MaxToolNameLength_Boundary(t *testing.T) {
	s := NewSanitizer()

	// Exactly 255 characters should be valid
	maxLengthName := "a" + strings.Repeat("b", 254)
	if len(maxLengthName) != 255 {
		t.Fatalf("maxLengthName length = %d, want 255", len(maxLengthName))
	}

	err := s.ValidateToolName(maxLengthName)
	if err != nil {
		t.Errorf("ValidateToolName(255 chars) = %v, want nil", err)
	}
}

func TestSanitizer_MaxStringLength_Boundary(t *testing.T) {
	s := NewSanitizer()

	// Exactly MaxStringLength should not be truncated
	exactLength := strings.Repeat("a", MaxStringLength)
	result, err := s.SanitizeValue(exactLength)
	if err != nil {
		t.Fatalf("SanitizeValue error = %v", err)
	}

	str, ok := result.(string)
	if !ok {
		t.Fatalf("result is not string: %T", result)
	}

	if len(str) != MaxStringLength {
		t.Errorf("len(result) = %d, want %d", len(str), MaxStringLength)
	}

	// One byte over should be truncated
	overLength := strings.Repeat("a", MaxStringLength+1)
	result, err = s.SanitizeValue(overLength)
	if err != nil {
		t.Fatalf("SanitizeValue error = %v", err)
	}

	str, ok = result.(string)
	if !ok {
		t.Fatalf("result is not string: %T", result)
	}

	if len(str) != MaxStringLength {
		t.Errorf("len(result) = %d, want %d", len(str), MaxStringLength)
	}
}
