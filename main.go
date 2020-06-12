package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
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
	LogDir         string   `json:"logDir"`
	LogName        string   `json:"logName"`
	RepRate        int      `json:"repRateSeconds"`
	ReportServices int      `json:"reportServices"`
	DontReport     []string `json:"dontReport"`
}

var version = "test"

func main() {
	conf, err := loadConf("/etc/failstats.conf")

	if err != nil {
		log.Fatalf(err.Error())
	}

	UUID, err := fetchUUID("/var/lib/failstats/uuid")
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Println("Version " + version)
	log.Println("Loaded settings")

	_, err = processBans(conf.LogDir, conf.LogName, UUID, conf.ReportServices, conf.DontReport, "/var/lib/failstats/lastrun")
	if err != nil {
		log.Fatal("Quitting due to error")
	}

	// Loops forever, should use negligible resources
	for range time.NewTicker(time.Duration(conf.RepRate) * time.Second).C {
		_, err = processBans(conf.LogDir, conf.LogName, UUID, conf.ReportServices, conf.DontReport, "/var/lib/failstats/lastrun")
		if err != nil {
			log.Fatal("Quitting due to error")
		}
	}
}

// Load config file
func loadConf(confFile string) (Configuration, error) {
	bytes, err := ioutil.ReadFile(confFile)
	var conf Configuration
	if err != nil {
		log.Println("Failed to access configuration file")
		return conf, err
	}

	err = json.Unmarshal(bytes, &conf)
	if err != nil {
		log.Println("Failed to load configuration file")
		return conf, err
	}

	return conf, nil
}

// Helper function - checks if string str is in slice list
func stringInStringSlice(str string, list []string) bool {
	for _, st := range list {
		if st == str {
			return true
		}
	}
	return false
}

// Processes the fail2ban logs, parses out all the new bans after a given datetime
func processBans(logDir string, logName string, guuid string, reportServices int, dontReport []string, lastRunLocation string) (int, error) {
	// Finds log files
	logFiles, err := findLogFiles(logDir, logName)

	if err != nil {
		return 0, err
	}

	// Gets last run
	lastRunTime, err := lastRun(lastRunLocation)

	if err != nil {
		return 0, err
	}

	// Gets current timezone offset
	t := time.Now()
	_, offset := t.Zone()

	var scanner *bufio.Scanner
	var banDates []string
	var banIPs []string
	var services []string

	re := regexp.MustCompile(`(?i)(\d+-\d+-\d+ \d+:\d+:\d+,\d+)\sfail2ban.actions\W+.*\WNOTICE\W+.*\[(.*)\].*Ban (.*)`)
	current := lastRunTime

	// Parses the file into the above variables
	for _, file := range logFiles {
		logFile, err := os.Open(logDir + file)

		if err != nil {
			return 0, err
		}

		defer logFile.Close()

		// Checks if file needs gzip
		if file[len(file)-3:] == ".gz" {
			gz, err := gzip.NewReader(logFile)

			if err != nil {
				return 0, err
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
					return 0, err
				}

				// Its late and date.equals doesn't seem to work, even if I set the locations to be the same
				if lastRunTime.Format("2006-01-02 15:04:05") == date.Format("2006-01-02 15:04:05") {
					continue
				}

				if date.After(lastRunTime) {
					// Converts to UTC time
					utcDate := date.Add(time.Duration(-offset) * time.Second)

					banDates = append(banDates, utcDate.Format("2006-01-02 15:04:05")+" UTC+0000")

					// Checks if service information can be reported at all
					if reportServices == 0 {
						services = append(services, "undisclosed")
					} else {
						// Checks if current matched service is in the list of services that shouldn't be reported
						if len(dontReport) == 0 {
							services = append(services, string(matches[2]))
						} else {
							if stringInStringSlice(string(matches[2]), dontReport) {
								services = append(services, "undisclosed")
							} else {
								services = append(services, string(matches[2]))
							}
						}
					}

					banIPs = append(banIPs, string(matches[3]))
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
		return 1, nil
	}

	// Puts data into one var
	var data [][]string
	for i := 0; i <= len(banDates)-1; i++ {
		data = append(data, []string{banDates[i], banIPs[i], services[i]})
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Println("Failed to create json")
		return 0, err
	}

	// Saves to gzip file
	file, err := ioutil.TempFile("/tmp/", "data.json.gz")

	if err != nil {
		log.Println("Failed to make json gzip")
		return 0, err
	}

	gzipFile := gzip.NewWriter(file)
	_, err = gzipFile.Write(jsonData)

	if err != nil {
		log.Println("Failed to write json to file")
		os.Remove(file.Name())
		return 0, err
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
		os.Remove(file.Name())
		return 0, err
	}

	id.Write([]byte(guuid))

	// POST version data
	versionPost, err := writer.CreateFormField("version")

	if err != nil {
		log.Println("Failed create post request")
		os.Remove(file.Name())
		return 0, err
	}

	versionPost.Write([]byte(version))

	// Adds GZIP file
	fileData, err := writer.CreateFormFile("data", "data.json.gz")

	if err != nil {
		log.Println("Failed create post request")
		os.Remove(file.Name())
		return 0, err
	}

	// Reopens data.json.gz
	fileLocation := file.Name()
	file, err = os.Open(fileLocation)
	if err != nil {
		log.Println("Failed create post request")
		os.Remove(fileLocation)
		return 0, err
	}

	_, err = io.Copy(fileData, file)

	if err != nil {
		log.Println("Failed create post request")
		os.Remove(file.Name())
		return 0, err
	}

	// Terminating boundary
	writer.Close()
	os.Remove(file.Name())

	// Creates the request
	request, err := http.NewRequest("POST", "https://failstats.net/api/", buf)

	if err != nil {
		log.Println("Failed create post request")
		return 0, err
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())

	// Deletes temp file
	os.Remove(file.Name())

	// Does the request and checks
	client := new(http.Client)
	result, err := client.Do(request)

	if err != nil {
		log.Println("Failed to connect to server")
		return 0, err
	}

	scanner = bufio.NewScanner(result.Body)
	scanner.Scan()

	if scanner.Text() != "1" {
		log.Println("Failed to transfer data - code: " + scanner.Text())
		return 0, errors.New("Failed to transfer data")
	}

	// Saves the last run
	err = saveRun(current, lastRunLocation)

	if err != nil {
		return 0, err
	}
	log.Println(len(banIPs), "bans proccessed")

	return 2, nil
}

// Finds the log files, errors out if failed. Returns a list of matching fileinfos
func findLogFiles(logDir string, logName string) ([]string, error) {
	files, err := ioutil.ReadDir(logDir)
	if err != nil {
		log.Println("Failed to find log directory: " + logDir)
		return nil, err
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
		log.Println("No fail2ban logs found")
		err = errors.New("Check fail2ban log path - no log files found")
		return nil, err
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

	return logFiles, nil
}

// Reverses slice and returns it
func reverseStrSlice(data []string) []string {
	var reversedStr []string
	for i := len(data) - 1; i >= 0; i-- {
		reversedStr = append(reversedStr, data[i])
	}

	return reversedStr
}

// Gets the last run time from lastRunFile
func lastRun(lastRunFile string) (time.Time, error) {
	// Checks if file exists
	fileStat, err := os.Stat(lastRunFile)

	defaultTime := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)

	if err != nil {
		if os.IsNotExist(err) {
			log.Println("No lastrun file exists - defaulting to 01:01 1/1/1")
			return defaultTime, nil
		}
		log.Println("Unable to access " + lastRunFile)
		return defaultTime, err
	}

	if fileStat.IsDir() {
		return defaultTime, errors.New(lastRunFile + " is a directory")
	}

	timeFile, err := os.Open(lastRunFile)
	if err != nil {
		log.Println("Failed to open " + lastRunFile)
		return defaultTime, err
	}
	defer timeFile.Close()

	scanner := bufio.NewScanner(timeFile)

	scanner.Scan()

	timeStr := scanner.Text()
	lastR, err := time.Parse(time.RFC3339, timeStr)

	if err != nil {
		log.Println("Unable to parse last run time from " + lastRunFile)
		return defaultTime, err
	}

	return lastR, nil
}

// Gets the UUID from uuidFile or generates a new one
func fetchUUID(uuidFilePath string) (string, error) {
	// Checks if file exists
	fi, err := os.Stat(uuidFilePath)

	if err != nil {
		if os.IsNotExist(err) {
			// Generates new one and saves
			log.Println("No UUID found, generating new one")
			guuid, err := uuid.NewV4()
			id := guuid.String()

			if err != nil {
				log.Println("Failed to generate new UUID")
				return "", err
			}

			// Read Write Mode
			file, err := os.Create(uuidFilePath)

			if err != nil {
				log.Println("Failed to save new uuid to " + uuidFilePath)
				return "", err
			}

			defer file.Close()

			file.WriteString(id)
			log.Println("Generated new uuid:", id)
			return id, nil
		}

		log.Println("Unable to access " + uuidFilePath)
		return "", err
	}

	// Checks if file is actually a directory
	if fi.Mode().IsDir() {
		return "", errors.New(uuidFilePath + " is a directory")
	}

	uuidFile, err := os.Open(uuidFilePath)
	if err != nil {
		log.Println("Failed to open " + uuidFilePath)
		return "", err
	}
	defer uuidFile.Close()

	scanner := bufio.NewScanner(uuidFile)

	scanner.Scan()

	id := scanner.Text()

	return id, nil
}

// Saves the last runtime to lastRunFile, creating file if it doesn't exist
func saveRun(timeStr time.Time, lastRunFile string) error {
	timeString := timeStr.Format(time.RFC3339)

	// Read Write Mode
	file, err := os.Create(lastRunFile)

	if err != nil {
		log.Println("Failed to save last runtime to " + lastRunFile)
		return err
	}

	defer file.Close()

	file.WriteString(timeString)

	return nil
}
