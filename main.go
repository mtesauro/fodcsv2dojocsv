package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type dojoCsv struct {
	date          string
	title         string
	cweID         string
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
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Printf("Error closing file %+v. Error was:\n%+v\n", fileName, err)
			os.Exit(1)
		}
	}()

	// Read the file into a [][]string
	r := csv.NewReader(f)

	lines, err := r.ReadAll()
	if err != nil {
		return [][]string{}, err
	}

	return lines, nil
}

func convertCSV(old *[][]string, dateStr string) []dojoCsv {
	// Setup the slice to return and append data to as needed during the conversion
	newCsv := make([]dojoCsv, 1)

	// Add in the header row
	newCsv[0] = dojoCsv{"Date", "Title", "CweId", "Url", "Severity", "Description", "Mitigation",
		"Impact", "References", "Active", "Verified", "FalsePositive", "Duplicate"}

	// Convert string argument to time type to use in for loop below
	filterDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		// Can't convert -scanDate to a time type so bail
		fmt.Printf("Unable to parse the provided -scanDate, unable to convert file.  Error was:\n%+v", err)
		os.Exit(1)
	}

	// Convert old lines to the new format
	for l, val := range *old {
		//Skip the first line aka header row of csv
		if l == 0 {
			continue
		}

		// Convert date string in this line to time type to compare later - format is 2019/08/22
		lineDate, err := time.Parse("2006/01/02", val[27])
		if err != nil {
			// Can't convert this line's date to a time type so bail
			fmt.Printf("Unable to parse the date in FoD CSV line %+v, unable to continue.  Error was:\n%+v", (l + 1), err)
			os.Exit(1)
		}
		// Check if the results for this line are too early, and skip if so
		if filterDate.After(lineDate) {
			// Provided -scanDate is after date of current line of FoD csv - so skip this line
			continue
		}

		// Build the next dojoCsv struct to add to newCsv
		// mapping from [dojo csv value]: [value from FoD] or in some cases text + multiple values from FoD
		nextLine := dojoCsv{
			date:        val[27],                      // Date from 'Scan completed date'
			title:       (val[10] + " in " + val[20]), // Title from 'Category' + 'location'
			cweID:       fixCwe(val[18]),              // Fix the CWE from CWE-404 to 404 (int) which Dojo expects
			url:         "",                           // url doens't make sense for SAST resutls
			severity:    val[9],                       // severity from 'Severity'
			description: val[23],                      // description from 'Description'
			// Create a mitigation block using location details from FoD
			// specifically file name, location, line number and full path
			mitigation: ("Update the vulnerability in " + val[20] + " at line " +
				val[25] + "\nFull path: " + val[32]),
			// Provide a direct link to the FoD website to understand impact
			impact: ("For full details, see " + val[0]),
			// Generate a link to the CWE reported by FoD
			references:    ("https://cwe.mitre.org/data/definitions/" + fixCwe(val[18]) + ".html"),
			active:        "TRUE",  // default this to true
			verified:      "TRUE",  // default this to true
			falsePositive: "FALSE", // default this to false
			duplicate:     "FALSE", // default this to false
		}
		newCsv = append(newCsv, nextLine)
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
	if len(right) < 2 {
		// if sanity check fails, return "1" as that won't break the import & is a deprecated CWE
		return "1"
	}
	re := regexp.MustCompile(`[[:digit:]]`)
	if re.Match([]byte(right[1])) {
		return right[1]
	}
	// if sanity check fails, return "1" as that won't break the import & is a deprecated CWE
	return "1"
}

func writeCSV(fileLines []dojoCsv, fname string) error {
	// TODO: Check if file already exists and bail if it does

	// Create the file for the converted CSV data
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Printf("Error closing file %+v. Error was:\n%+v\n", fname, err)
			os.Exit(1)
		}
	}()

	// Setup a CSV writer
	w := csv.NewWriter(f)
	defer w.Flush()

	for _, val := range fileLines {
		//fmt.Printf("val.title is %+v\n", val.title)
		line := []string{
			val.date,
			val.title,
			val.cweID,
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
	// Handle the command-line arguments for file name and 'scan on' date
	fileArg := flag.String("inCsv", "", "Provide the file path to a FoD CSV file")
	dateArg := flag.String("scanDate", "", "Only results newer than date - use format YYYY-MM-DD")
	flag.Parse()

	// Sanity check the command-line arguements
	if len(os.Args) != 5 {
		// Both arguments are required
		fmt.Println("ERROR - Not enough command-line arguments sent")
		fmt.Println("")
		fmt.Println("Usage: fodcsv2dojocsv -inCsv [file path] -scanDate [YYY-MM-DD]")
		fmt.Println("      -inCsv [file path]")
		fmt.Println("        	Provide the file path to a FoD CSV file")
		fmt.Println("        	e.g. -inCsv ./csv-from-fod.csv")
		fmt.Println("      -scanDate [date in YYYY-MM-DD]")
		fmt.Println("        	Only results newer than date - use format YYYY-MM-DD")
		fmt.Println("        	e.g. -scanDate 2019-08-30")
		fmt.Println("\n=> fodcsv2dojocsv version 1.0")
		os.Exit(1)
	}

	//inFile := "./example-FoD-csv-output.csv"
	lines, err := readCsv(*fileArg)
	if err != nil {
		fmt.Printf("Unable to read file named %s\nError was:\n\t%+v\n", *fileArg, err)
		os.Exit(1)
	}

	// Convert the lines from the FoD csv format to the Dojo csv format
	newLines := convertCSV(&lines, *dateArg)

	// Write out the new Dojo csv formatted file
	outFile := strings.Replace(strings.ToLower(*fileArg), ".csv", "", -1) + "-Dojo-safe.csv"
	err = writeCSV(newLines, outFile)
	if err != nil {
		fmt.Printf("Error writing new CSV file.  Error was:\n%+v", err)
	}

	// Why not?
	fmt.Println("\nGood so far...")
}
