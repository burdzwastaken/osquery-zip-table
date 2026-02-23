package zip

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

func TestSearchZipFile_NoConstraint(t *testing.T) {
	_, err := searchZipFile(context.Background(), table.QueryContext{Constraints: map[string]table.ConstraintList{}})
	if !errors.Is(err, ErrMissingConstraint) {
		t.Fatalf("expected ErrMissingConstraint, got %v", err)
	}
}

func TestSearchZipFile_Valid(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "pkgzip-*.zip")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }() //nolint:gosec // temp file created by os.CreateTemp

	w := zip.NewWriter(tmpFile)
	entries := map[string][]byte{
		"hello.txt":     []byte("hello world"),
		"subdir/foo.md": []byte("content"),
	}
	for name, data := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("unable to add %s: %v", name, err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatalf("unable to write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to finalize zip: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	qc := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"zip_file": {Constraints: []table.Constraint{{Expression: tmpFile.Name()}}},
		},
	}
	rows, err := searchZipFile(context.Background(), qc)
	if err != nil {
		t.Fatalf("searchZipFile failed: %v", err)
	}
	if len(rows) != len(entries) {
		t.Fatalf("expected %d rows, got %d", len(entries), len(rows))
	}

	byName := make(map[string]map[string]string, len(rows))
	for _, row := range rows {
		byName[row["file_name"]] = row
	}

	for name, data := range entries {
		row, ok := byName[name]
		if !ok {
			t.Errorf("missing entry for %s", name)
			continue
		}
		if got := row["zip_file"]; got != tmpFile.Name() {
			t.Errorf("zip_file = %q, want %q", got, tmpFile.Name())
		}
		for _, col := range []string{
			"crc32", "method", "flags", "creator_version",
			"reader_version", "external_attrs", "extra_length",
		} {
			if _, found := row[col]; !found {
				t.Errorf("row missing column %s", col)
			}
		}
		extra, err := strconv.Atoi(row["extra_length"])
		if err != nil {
			t.Errorf("invalid extra_length %q: %v", row["extra_length"], err)
		} else if extra != 0 {
			t.Errorf("expected extra_length=0, got %d", extra)
		}
		size, err := strconv.Atoi(row["uncompressed_size"])
		if err != nil {
			t.Errorf("invalid uncompressed_size %q: %v", row["uncompressed_size"], err)
		} else if size != len(data) {
			t.Errorf("uncompressed_size = %d, want %d", size, len(data))
		}
	}
}
