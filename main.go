package main

import (
	"bufio"
	"compress/gzip"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	// Gets current timezone
	t := time.Now()
	zone, offset := t.Zone()

	logFolder := "/var/log/"
	logName := "fail2ban"

	println(zone, offset)
	processBans(logFolder, logName)
}

// Processes the fail2ban logs, parses out all the new bans after a given datetime
func processBans(logFolder string, logName string) {
	// Finds log files
	logFiles := findLogFiles(logFolder, logName)

	var scanner *bufio.Scanner
	re := regexp.MustCompile(`(?i)(\d+-\d+-\d+ \d+:\d+:\d+,\d+)\sfail2ban.actions\W+.*\WBan (.*)`)

	// Parses the files
	for _, file := range logFiles {
		logFile, err := os.Open(logFolder + file)

		if err != nil {
			log.Fatal(err)
		}

		defer logFile.Close()

		// Checks if file needs gzip
		if file[len(file)-3:] == ".gz" {
			gz, err := gzip.NewReader(logFile)

			if err != nil {
				log.Fatal(err)
			}

			defer gz.Close()

			scanner = bufio.NewScanner(gz)
		} else {
			// Plain text file
			scanner = bufio.NewScanner(logFile)
		}

		// Reads through text file
		for scanner.Scan() {
			matches := re.FindSubmatch([]byte(scanner.Text()))

			if matches != nil {

				println(string(matches[1]), string(matches[2]))
			}
		}
	}
}

// Finds the log files, errors out if failed. Returns a list of matching fileinfos
func findLogFiles(logFolder string, logName string) []string {
	files, err := ioutil.ReadDir(logFolder)
	if err != nil {
		log.Fatal(err)
	}

	re := regexp.MustCompile(logName)
	var logFiles []string
	logRotate := "normal"

	// Gets all of the fail2ban log files, sorted alphabetically
	for _, f := range files {
		if re.Match([]byte(f.Name())) {
			logFiles = append(logFiles, f.Name())

			if strings.Contains(f.Name(), "-") {
				logRotate = "date"
			}
		}
	}

	if len(logFiles) == 0 {
		log.Fatal("No fail2ban logs found")
	}

	// Orders the slice of log files. Newest first
	if logRotate == "normal" {
		// Apparently do nothing, this is only here for the sake of readability
		// This appears to be the case on ubuntu/debian
	} else if logRotate == "date" {
		// This is the case on centos systems, so reverses the list, then moves "fail2ban.log"
		// back to the front
		logFiles = append(logFiles[1:], "fail2ban.log")
		logFiles = reverseStrSlice(logFiles)

	}

	return logFiles
}

// Reverses slice and returns it
func reverseStrSlice(data []string) []string {
	var reversedStr []string
	for i := len(data) - 1; i >= 0; i-- {
		reversedStr = append(reversedStr, data[i])
	}

	return reversedStr
}
