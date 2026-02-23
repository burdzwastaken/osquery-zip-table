package zip

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
)

// ErrMissingConstraint is returned when the required zip_file constraint is not provided.
var ErrMissingConstraint = errors.New("the zip table requires that you specify a constraint WHERE zip_file =")

func New() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("zip_file"),
		table.TextColumn("file_name"),
		table.TextColumn("comment"),
		table.TextColumn("modified"),
		table.TextColumn("non_utf8"),
		table.BigIntColumn("compressed_size"),
		table.BigIntColumn("uncompressed_size"),
		table.BigIntColumn("crc32"),
		table.BigIntColumn("method"),
		table.BigIntColumn("flags"),
		table.BigIntColumn("creator_version"),
		table.BigIntColumn("reader_version"),
		table.BigIntColumn("external_attrs"),
		table.BigIntColumn("extra_length"),
	}
	return table.NewPlugin("zip", columns, searchZipFile)
}

func searchZipFile(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	f, ok := queryContext.Constraints["zip_file"]
	if !ok || len(f.Constraints) == 0 {
		return nil, ErrMissingConstraint
	}
	where := f.Constraints[0].Expression
	read, err := zip.OpenReader(where)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file %s: %w", where, err)
	}
	defer func() { _ = read.Close() }()

	resp := make([]map[string]string, 0, len(read.File))
	for _, file := range read.File {
		m := make(map[string]string, 14)
		m["zip_file"] = where
		m["file_name"] = file.Name
		m["comment"] = file.Comment
		m["modified"] = file.Modified.String()
		m["non_utf8"] = strconv.FormatBool(file.NonUTF8)
		m["compressed_size"] = strconv.FormatUint(file.CompressedSize64, 10)
		m["uncompressed_size"] = strconv.FormatUint(file.UncompressedSize64, 10)
		m["crc32"] = strconv.FormatUint(uint64(file.CRC32), 10)
		m["method"] = strconv.FormatUint(uint64(file.Method), 10)
		m["flags"] = strconv.FormatUint(uint64(file.Flags), 10)
		m["creator_version"] = strconv.FormatUint(uint64(file.CreatorVersion), 10)
		m["reader_version"] = strconv.FormatUint(uint64(file.ReaderVersion), 10)
		m["external_attrs"] = strconv.FormatUint(uint64(file.ExternalAttrs), 10)
		m["extra_length"] = strconv.Itoa(len(file.Extra))
		resp = append(resp, m)
	}
	return resp, nil
}
