package zip

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
)

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
		return nil, errors.New("The zip table requires that you specify a constraint WHERE zip_file =")
	}
	where := f.Constraints[0].Expression
	read, err := zip.OpenReader(where)

	if err != nil {
		return nil, fmt.Errorf("failed to open zip file %s: %w", where, err)
	}
	defer read.Close()

	var resp []map[string]string
	for _, file := range read.File {
		if err := listFiles(file); err != nil {
			return nil, fmt.Errorf("reading file %s from zip %s: %w", file.Name, where, err)
		}
		m := make(map[string]string, 14)
		m["zip_file"] = where
		m["file_name"] = file.Name
		m["comment"] = file.Comment
		m["modified"] = file.Modified.String()
		m["non_utf8"] = strconv.FormatBool(file.NonUTF8)
		m["compressed_size"] = strconv.Itoa(int(file.CompressedSize64))
		m["uncompressed_size"] = strconv.Itoa(int(file.UncompressedSize64))
		m["crc32"] = strconv.Itoa(int(file.CRC32))
		m["method"] = strconv.Itoa(int(file.Method))
		m["flags"] = strconv.Itoa(int(file.Flags))
		m["creator_version"] = strconv.Itoa(int(file.CreatorVersion))
		m["reader_version"] = strconv.Itoa(int(file.ReaderVersion))
		m["external_attrs"] = strconv.Itoa(int(file.ExternalAttrs))
		m["extra_length"] = strconv.Itoa(len(file.Extra))
		resp = append(resp, m)
	}
	return resp, nil
}

func listFiles(file *zip.File) error {
	reader, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open zip entry %s: %w", file.Name, err)
	}
	defer reader.Close()

	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("failed to read zip entry %s: %w", file.Name, err)
	}
	return nil
}
