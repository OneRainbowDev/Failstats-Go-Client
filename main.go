package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// Configuration struct
type Configuration struct {
	UUID    string `json:"uuid"`
	LogDir  string `json:"logDir"`
	LogName string `json:"logName"`
}

func main() {
	conf := loadConf()

	processBans(conf.LogDir, conf.LogName)
}

// Load config file
func loadConf() Configuration {
	bytes, err := ioutil.ReadFile("/etc/failstats.conf")
	if err != nil {
		log.Fatal(err)
	}

	var conf Configuration
	err = json.Unmarshal(bytes, &conf)
	if err != nil {
		log.Fatal(err)
	}

	return conf
}

// Processes the fail2ban logs, parses out all the new bans after a given datetime
func processBans(logDir string, logName string) {
	// Finds log files
	logFiles := findLogFiles(logDir, logName)

	// Gets last run
	lastRunTime := lastRun()

	// Gets current timezone offset
	t := time.Now()
	_, offset := t.Zone()

	var scanner *bufio.Scanner
	var banDates []string
	var banIPs []string
	re := regexp.MustCompile(`(?i)(\d+-\d+-\d+ \d+:\d+:\d+,\d+)\sfail2ban.actions\W+.*\WBan (.*)`)
	current := lastRunTime

	// Parses the file into the above variables
	for _, file := range logFiles {
		logFile, err := os.Open(logDir + file)

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
		lastFile := false
		for scanner.Scan() {
			matches := re.FindSubmatch([]byte(scanner.Text()))

			if matches != nil {
				dateStr := strings.Replace(string(matches[1]), ",", ".", -1)
				date, err := time.Parse("2006-01-02 15:04:05.000", dateStr)

				if err != nil {
					log.Println("Failed to parse date.")
					log.Fatal(err)
				}

				if date.After(lastRunTime) {
					// Converts to UTC time
					utcDate := date.Add(time.Duration(-offset) * time.Second)

					banDates = append(banDates, utcDate.Format("2006-01-02 15:04:05")+" UTC+0000")
					banIPs = append(banIPs, string(matches[2]))
				} else {
					// Has to complete the file
					lastFile = true
				}

				if date.After(current) {
					current = date
				}
			}
		}

		if lastFile {
			break
		}
	}

	// Saves the last run
	saveRun(lastRunTime)
}

// Finds the log files, errors out if failed. Returns a list of matching fileinfos
func findLogFiles(logDir string, logName string) []string {
	files, err := ioutil.ReadDir(logDir)
	if err != nil {
		log.Println("Failed to find log directory: " + logDir)
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

// Gets the last runtime from \var\lib\failstats
func lastRun() time.Time {
	// Checks if file exists
	_, err := os.Stat("/var/lib/failstats")

	if err != nil {
		if os.IsNotExist(err) {
			return time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
		}
		log.Println("Unable to access /var/lib/failstats")
		log.Fatal(err)
	}

	timeFile, err := os.Open("/var/lib/failstats")
	if err != nil {
		log.Fatal(err)
	}
	defer timeFile.Close()

	scanner := bufio.NewScanner(timeFile)

	scanner.Scan()

	timeStr := scanner.Text()
	lastR, err := time.Parse(time.RFC3339, timeStr)

	if err != nil {
		log.Println("Unable to parse last run time from /var/lib/failstats")
		log.Fatal(err)
	}

	return lastR
}

// Saves the last runtime to \var\lib\failstats, creating file if it doesn't exist
func saveRun(timeStr time.Time) {
	timeString := timeStr.Format(time.RFC3339)

	// Read Write Mode
	file, err := os.Create("/var/lib/failstats")

	if err != nil {
		log.Println("Failed to save last runtime to /var/lib/failstats")
		log.Fatal(err)
	}

	defer file.Close()

	file.WriteString(timeString)
}
