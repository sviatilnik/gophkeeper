package main

import "fmt"

var (
	buildVersion string
	buildDate    string
	buildCommit  string
)

func main() {
	fmt.Println("GophKeeper client")

	printBuildInfo()
}

func printBuildInfo() {
	version := buildVersion
	if version == "" {
		version = "N/A"
	}

	date := buildDate
	if date == "" {
		date = "N/A"
	}

	commit := buildCommit
	if commit == "" {
		commit = "N/A"
	}

	fmt.Printf("version: %s\n", version)
	fmt.Printf("date: %s\n", date)
	fmt.Printf("commit: %s\n", commit)
}
