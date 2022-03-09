package main

import (
	"flag"
	"log"
	"time"

	"github.com/burdzwastaken/osquery-zip-table/pkg/zip"
	osquery "github.com/osquery/osquery-go"
)

func main() {
	var (
		flSocketPath = flag.String("socket", "", "")
		flTimeout    = flag.Int("timeout", 0, "")
		_            = flag.Int("interval", 0, "")
		_            = flag.Bool("verbose", false, "")
	)
	flag.Parse()

	// allow for osqueryd to create the socket path
	time.Sleep(2 * time.Second)

	// create an extension server
	server, err := osquery.NewExtensionManagerServer(
		"com.burdzwastaken.osquery_zip_table",
		*flSocketPath,
		osquery.ServerTimeout(time.Duration(*flTimeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// create and register s3 config plugin.
	// requires configuration to be available through environment variables.
	server.RegisterPlugin(zip.New())

	// run the extension server
	log.Fatal(server.Run())
}
