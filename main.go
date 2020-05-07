package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gofrs/uuid"
)

// Configuration struct
type Configuration struct {
	LogDir  string `json:"logDir"`
	LogName string `json:"logName"`
	RepRate int    `json:"repRateSeconds"`
}

func main() {
	conf := loadConf()
	UUID := fetchUUID()

	log.Println("Loaded settings")

	processBans(conf.LogDir, conf.LogName, UUID)

	// Loops forever, should use negligible resources
	for range time.NewTicker(time.Duration(conf.RepRate) * time.Second).C {
		processBans(conf.LogDir, conf.LogName, UUID)
	}
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
func processBans(logDir string, logName string, guuid string) {
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

				// Its late and date.equals doesn't seem to work, even if I set the locations to be the same
				if lastRunTime.Format("2006-01-02 15:04:05") == date.Format("2006-01-02 15:04:05") {
					continue
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

	// Checks if there is data to send, returns otherwise
	if len(banIPs) == 0 {
		log.Println("0 bans proccessed")
		return
	}

	// Puts data into one var
	var data [][]string
	for i := 0; i <= len(banDates)-1; i++ {
		data = append(data, []string{banDates[i], banIPs[i]})
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Println("Failed to create json")
		log.Fatal(err)
	}

	// Saves to gzip file
	file, err := ioutil.TempFile("/tmp/", "data.json.gz")

	if err != nil {
		log.Println("Failed to make json gzip")
		log.Fatal(err)
	}

	gzipFile := gzip.NewWriter(file)
	_, err = gzipFile.Write(jsonData)

	if err != nil {
		log.Println("Failed to write json to file")
		log.Fatal(err)
		os.Remove(file.Name())
	}

	gzipFile.Close()

	// Flushes gzip data to disk
	file.Close()

	// Creates the post data manually since there is no convenient function
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)

	// POST ID data
	id, err := writer.CreateFormField("id")

	if err != nil {
		log.Println("Failed create post request")
		log.Fatal(err)
		os.Remove(file.Name())
	}

	id.Write([]byte(guuid))

	// Adds GZIP file
	fileData, err := writer.CreateFormFile("data", "data.json.gz")

	if err != nil {
		log.Println("Failed create post request")
		log.Fatal(err)
		os.Remove(file.Name())
	}

	// Reopens data.json.gz
	fileLocation := file.Name()
	file, err = os.Open(fileLocation)
	if err != nil {
		log.Println("Failed create post request")
		log.Fatal(err)
		os.Remove(fileLocation)
	}

	_, err = io.Copy(fileData, file)

	if err != nil {
		log.Println("Failed create post request")
		log.Fatal(err)
		os.Remove(file.Name())
	}

	// Terminating boundary
	writer.Close()
	os.Remove(file.Name())

	// Creates the request
	request, err := http.NewRequest("POST", "https://failstats.net/api/", buf)

	if err != nil {
		log.Println("Failed create post request")
		log.Fatal(err)
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())

	// Deletes temp file
	os.Remove(file.Name())

	// Does the request and checks
	client := new(http.Client)
	result, err := client.Do(request)

	if err != nil {
		log.Println("Failed to connect to server")
		log.Println(err)
		return
	}

	scanner = bufio.NewScanner(result.Body)
	scanner.Scan()

	if scanner.Text() != "1" {
		log.Println("Failed to transfer data")
		return
	}

	// Saves the last run
	saveRun(current)
	log.Println(len(banIPs), "bans proccessed")
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

// Gets the last run time from \var\lib\failstats
func lastRun() time.Time {
	// Checks if file exists
	_, err := os.Stat("/var/lib/failstats/lastrun")

	if err != nil {
		if os.IsNotExist(err) {
			log.Println("No lastrun file exists, generating new one")
			return time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
		}
		log.Println("Unable to access /var/lib/failstats/lastrun")
		log.Fatal(err)
	}

	timeFile, err := os.Open("/var/lib/failstats/lastrun")
	if err != nil {
		log.Fatal(err)
	}
	defer timeFile.Close()

	scanner := bufio.NewScanner(timeFile)

	scanner.Scan()

	timeStr := scanner.Text()
	lastR, err := time.Parse(time.RFC3339, timeStr)

	if err != nil {
		log.Println("Unable to parse last run time from /var/lib/failstats/lastrun")
		log.Fatal(err)
	}

	return lastR
}

// Gets the UUID from \var\lib\failstats or generates a new one
func fetchUUID() string {
	// Checks if file exists
	_, err := os.Stat("/var/lib/failstats/uuid")

	if err != nil {
		if os.IsNotExist(err) {
			// Generates new one and saves
			guuid, err := uuid.NewV4()
			id := guuid.String()

			if err != nil {
				log.Fatal(err)
			}

			// Read Write Mode
			file, err := os.Create("/var/lib/failstats/uuid")

			if err != nil {
				log.Println("Failed to save new uuid to /var/lib/failstats/uuid")
				log.Fatal(err)
			}

			defer file.Close()

			file.WriteString(id)
			log.Println("Generated new uuid:", id)
			return id
		}

		log.Println("Unable to access /var/lib/failstats/uuid")
		log.Fatal(err)
	}

	uuidFile, err := os.Open("/var/lib/failstats/uuid")
	if err != nil {
		log.Fatal(err)
	}
	defer uuidFile.Close()

	scanner := bufio.NewScanner(uuidFile)

	scanner.Scan()

	id := scanner.Text()

	return id
}

// Saves the last runtime to \var\lib\failstats, creating file if it doesn't exist
func saveRun(timeStr time.Time) {
	timeString := timeStr.Format(time.RFC3339)

	// Read Write Mode
	file, err := os.Create("/var/lib/failstats/lastrun")

	if err != nil {
		log.Println("Failed to save last runtime to /var/lib/failstats/lastrun")
		log.Fatal(err)
	}

	defer file.Close()

	file.WriteString(timeString)
}
