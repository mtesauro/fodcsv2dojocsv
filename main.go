package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type dojoCsv struct {
	date          string
	title         string
	cweId         string
	url           string
	severity      string
	description   string
	mitigation    string
	impact        string
	references    string
	active        string
	verified      string
	falsePositive string
	duplicate     string
}

// Available fields in FoD csv
//Vulnerability Details Url
//Application
//Application ID
//Release
//Release ID
//FISMA
//STIG39
//STIG 4.1
//STIG 4.3
//Severity
//Category
//Kingdom
//OWASP 2004
//OWASP 2007
//OWASP 2010
//OWASP 2013
//OWASP 2014 Mobile Top 10
//OWASP 2017
//CWE
//Package
//Location
//VulnId
//Analysis Type
//Description
//Status
//Line Number
//Scan started date
//Scan completed date
//Has Comments
//Assigned User
//Scan Type
//Subtype
//LocationFull
//Has Attachments
//PCI 2.0
//SANS 2009
//SANS 2010
//SANS Top 25 2011
//WASC242
//Analyzer
//Is Suppressed
//Scan ID
//PCI 3.0
//Introduced Date
//SDLC Status
//Comments
//URL
//Bug Link
//ID
//CheckId
//Developer Status
//Auditor Status
//False Positive Challenge
//Closed Date
//Closed Status
//Instance ID
//PCI 3.1
//PCI 3.2
//Source
//Sink
//Days to Fix
//Bug Submitted
//BHS AppID

func readCsv(fileName string) ([][]string, error) {

	// Open the csv file
	f, err := os.Open(fileName)
	if err != nil {
		return [][]string{}, err

	}
	defer f.Close()

	// Read the file into a [][]string
	r := csv.NewReader(f)

	lines, err := r.ReadAll()
	if err != nil {
		return [][]string{}, err
	}

	return lines, nil
}

func convertCSV(old *[][]string) []dojoCsv {
	// Setup the slice to return that is the lenght of the one sent in (old)
	newCsv := make([]dojoCsv, len(*old))

	// Add in the header row
	newCsv[0] = dojoCsv{"Date", "Title", "CweId", "Url", "Severity", "Description", "Mitigation",
		"Impact", "References", "Active", "Verified", "FalsePositive", "Duplicate"}

	// Convert old lines to the new format
	for l, val := range *old {
		//Skip the first line aka header row of csv
		if l == 0 {
			continue
		}
		// TODO: Add if clause for date filtering (aka scans after [date]

		// Build the next dojoCsv struct to add to newCsv
		// mapping from [dojo csv value]: [value from FoD] or in some cases text + multiple values from FoD
		nextLine := dojoCsv{
			date:        val[27],                      // Date from 'Scan completed date'
			title:       (val[10] + " in " + val[20]), // Title from 'Category' + 'location'
			cweId:       fixCwe(val[18]),              // Fix the CWE from CWE-404 to 404 (int) which Dojo expects
			url:         "",                           // url doens't make sense for SAST resutls
			severity:    val[9],                       // severity from 'Severity'
			description: val[23],                      // description from 'Description'
			// Create a mitigation block using location details from FoD
			// specifically file name, location, line number and full path
			mitigation: ("Update the vulnerability in " + val[20] + " at line " +
				val[25] + "\nFull path: " + val[32]),
			impact: ("For full details, see " + val[0]),
			// Provide a direct link to the FoD website to understand impact
			references: ("https://cwe.mitre.org/data/definitions/" + fixCwe(val[18]) + ".html"),
			// Generate a link to the CWE reported by FoD
			active:        "TRUE",  // default this to true
			verified:      "TRUE",  // default this to true
			falsePositive: "FALSE", // default this to false
			duplicate:     "FALSE", // default this to false
		}
		newCsv[l] = nextLine
	}
	return newCsv
}

func fixCwe(wrong string) string {
	// First catch the case where FoD sends multiple CWEs like 'CWE-22, CWE-73'
	if strings.Contains(wrong, ",") {
		// Grab the second of 2+ CWEs provided as that seems to be the most specific one
		single := strings.Split(wrong, ",")
		wrong = single[1]
	}

	// Fod sends 'CWE-###' and Dojo want just ### so CWE-204 should change to 204
	right := strings.SplitAfterN(wrong, "-", 2)

	// Sanity check our split result
	re := regexp.MustCompile(`[[:digit:]]`)
	if re.Match([]byte(right[1])) {
		return right[1]
	}
	// if sanity check fails, return empty string as that's perferable to breaking the import
	return ""
}

func writeCSV(fileLines []dojoCsv, fname string) error {
	// Create the file for the converted CSV data
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	// Setup a CSV writer
	w := csv.NewWriter(f)
	defer w.Flush()

	for _, val := range fileLines {
		//fmt.Printf("val.title is %+v\n", val.title)
		line := []string{
			val.date,
			val.title,
			val.cweId,
			val.url,
			val.severity,
			val.description,
			val.mitigation,
			val.impact,
			val.references,
			val.active,
			val.verified,
			val.falsePositive,
			val.duplicate,
		}

		err := w.Write(line)
		if err != nil {
			return err
		}

	}

	return nil
}

func main() {
	// TODO: Read in file name from command line option
	inFile := "./example-FoD-csv-output.csv"
	lines, err := readCsv(inFile)
	if err != nil {
		fmt.Printf("Unable to read in file named %s\nError was:\n%+v", inFile, err)
		os.Exit(1)
	}

	// Convert the lines from the FoD csv format to the Dojo csv format
	newLines := convertCSV(&lines)

	// Write out the new Dojo csv formatted file
	outFile := strings.Replace(strings.ToLower(inFile), ".csv", "", -1) + "-Dojo-safe.csv"
	err = writeCSV(newLines, outFile)
	if err != nil {
		fmt.Printf("Error writing new CSV file.  Error was:\n%+v", err)
	}

	//fmt.Printf("\n%+v\n", newLines[1])
	// Why not?
	fmt.Println("\nGood so far...")
}
