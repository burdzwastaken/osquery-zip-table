package zip

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"log"
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
		table.BigIntColumn("uncommpressed_size"),
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
		msg := "Failed to open: %s"
		log.Fatalf(msg, err)
	}
	defer read.Close()

	var resp []map[string]string
	for _, file := range read.File {
		if err := listFiles(file); err != nil {
			log.Fatalf("Failed to read %s from zip: %s", file.Name, err)
		}
		m := make(map[string]string, 7)
		m["zip_file"] = where
		m["file_name"] = file.Name
		m["comment"] = file.Comment
		m["modified"] = file.Modified.String()
		m["non_utf8"] = strconv.FormatBool(file.NonUTF8)
		m["compressed_size"] = strconv.Itoa(int(file.CompressedSize64))
		m["uncommpressed_size"] = strconv.Itoa(int(file.UncompressedSize64))
		resp = append(resp, m)
	}
	return resp, nil
}

func listFiles(file *zip.File) error {
	fileread, err := file.Open()
	if err != nil {
		msg := "Failed to open zip %s for reading: %s"
		return fmt.Errorf(msg, file.Name, err)
	}
	defer fileread.Close()

	if err != nil {
		msg := "Failed to read zip %s for reading: %s"
		return fmt.Errorf(msg, file.Name, err)
	}
	return nil
}
