package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/fflewddur/demarcater/dmarc"
)

func main() {
	// For now, use the first argument as the file to parse
	if len(os.Args) != 2 {
		fmt.Println("Usage: demarcater [file or directory]")
		os.Exit(1)
	}

	path := os.Args[1]

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Error opening '%s': %v\n", path, err)
	}

	var reports []*dmarc.Report = make([]*dmarc.Report, 0)
	if info.IsDir() {
		reports = append(reports, readDir(path)...)
	} else {
		reports = append(reports, readFile(path))
	}

	passed := 0
	failed := 0
	for _, r := range reports {
		if r.AllPassed() {
			passed++
		} else {
			failed++
			fmt.Printf("\nFailure record:\n")
			r.PrettyPrint()
		}
	}

	fmt.Printf("\nScanned %d files\n", passed+failed)
}

func readDir(dir string) []*dmarc.Report {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("Could not read directory '%s': %v\n", dir, err)
		os.Exit(1)
	}

	var reports []*dmarc.Report = make([]*dmarc.Report, 0)
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		if e.IsDir() {
			reports = append(reports, readDir(p)...)
		} else {
			reports = append(reports, readFile(p))
		}
	}
	return reports
}

func readFile(path string) *dmarc.Report {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading '%s': %v\n", path, err)
		os.Exit(1)
	}

	if isZipArchive(data) {
		data = unzipBytes(data)
	}

	report, err := dmarc.ReadReport(data)
	if err != nil {
		fmt.Printf("Error parsing '%s': %v\n", path, err)
		os.Exit(1)
	}
	return report
}

func isZipArchive(data []byte) bool {
	contentType := http.DetectContentType(data)
	return contentType == "application/zip"
}

func unzipBytes(data []byte) []byte {
	var unzippedData []byte
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		fmt.Printf("Error decompressing: %v\n", err)
		os.Exit(1)
	}

	for _, file := range reader.File {
		zippedFile, err := file.Open()
		if err != nil {
			fmt.Printf("Error decompressing '%s': %v\n", file.Name, err)
			os.Exit(1)
		}
		var b bytes.Buffer
		_, err = b.ReadFrom(zippedFile)
		if err != nil {
			fmt.Printf("Error decompressing '%s': %v\n", file.Name, err)
			os.Exit(1)
		}
		unzippedData = b.Bytes()
	}
	return unzippedData
}
