# osquery-zip-table

An [osquery](https://osquery.io) table extension to list the contents of a ZIP archive.

## Building

To build the osquery extension you will need to have the following installed:
* [go](https://golang.org/) (version >= 1.20)
* [make](https://www.gnu.org/software/make/)

To build the extension, use:
```
make
```

## Usage

Load the extension into osqueryd:
```
osqueryd \
  --extensions_autoload=/tmp/extensions.load \
  --pidfile=/tmp/osquery.pid \
  --database_path=/tmp/osquery.db \
  --extensions_socket=/tmp/osquery.sock
```

Then you can query the `zip` table:
```
SELECT
  zip_file,
  file_name,
  comment,
  modified,
  non_utf8,
  compressed_size,
  uncompressed_size,
  crc32,
  method,
  flags,
  creator_version,
  reader_version,
  external_attrs,
  extra_length
FROM zip
WHERE zip_file = '/path/to/archive.zip';
```

## Troubleshooting

Run osqueryd/osqueryi with the `--verbose` flag to see extension logs.
If running as root, adjust ownership of `build/osquery-zip-table-extension.ext` or use the `--allow_unsafe` flag.

## Thanks

Inspired by [burdzwastaken/osquery-s3-config](https://github.com/burdzwastaken/osquery-s3-config).
