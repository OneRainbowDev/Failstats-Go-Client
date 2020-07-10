package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLdflags(t *testing.T) {
	if version != "test" {
		t.Fatalf("Not in test setup")
	}
}

func TestConfLoader(t *testing.T) {
	// Checks loading a non-existent conf file
	conf, err := loadConf("t.conf")
	if err == nil {
		t.Errorf("Somehow found a non-existent conf file....")
	}

	// Checks loading a malformed conf file
	conf, err = loadConf("test_data/malformed.conf")
	if err == nil {
		t.Errorf("Succesfully loads a malformed configuration file")
	}

	// Checks loading a valid conf file
	conf, err = loadConf("test_data/test.conf")
	if err != nil {
		t.Errorf("Should have loaded test.conf perfectly")
	}

	testFailure := false

	if len(conf.DontReport) != 1 && conf.DontReport[0] == "jupyter" {
		testFailure = true
	}
	if conf.LogDir != "test_data/" {
		testFailure = true
	}
	if conf.LogName != "fail2ban" {
		testFailure = true
	}
	if conf.RepRate != 3600 {
		testFailure = true
	}
	if conf.ReportServices != 1 {
		testFailure = true
	}

	if testFailure {
		t.Errorf("Conf file parser failed")
	}
}

func TestStringInStringSlice(t *testing.T) {
	testStr := []string{"test", "data", "rabbit", "beer"}

	if stringInStringSlice("test", testStr) != true {
		t.Errorf("String in slice checker failed")
	}
	if stringInStringSlice("wine", testStr) != false {
		t.Errorf("String in slice checker failed")
	}
}

func TestReverseStringSlice(t *testing.T) {
	testStr := []string{"test", "data", "rabbit", "beer"}

	if reflect.DeepEqual(reverseStrSlice(testStr), []string{"beer", "rabbit", "data", "test"}) != true {
		t.Errorf("String slice reverser failed")
	}
}

func TestUUIDLoader(t *testing.T) {
	// Tests non-existent file
	testFile := uuid.New().String()

	id, err := fetchUUID("/tmp/" + testFile)
	_, parseErr := uuid.Parse(id)

	if err != nil && id != "" && parseErr == nil {
		t.Errorf("Failed to generate new UUID")
	}

	// Tests already existing file
	id, err = fetchUUID("test_data/uuid")

	if err != nil {
		t.Errorf("Failed to read uuid file")
	}

	if id != "e55112e1-3233-4778-bd64-c6a33644ecfe" {
		t.Errorf("Read an unexpected UUID string")
	}

	// Tests an existing folder - not a file
	id, err = fetchUUID("test_data")

	if err == nil {
		println(err.Error())
		t.Errorf("Reads a directory as a uuid")
	}

	// Tests read only filesystem
	id, err = fetchUUID("/proc/test")

	if err == nil {
		t.Errorf("Somehow saved to a read-only system, please check your os")
	}
}

func TestLastRun(t *testing.T) {
	// Tests non-existent file
	lastRunTime, err := lastRun("test_data/testingNonExistentFiles")

	if err != nil || lastRunTime != time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC) {
		t.Errorf("Failed to generate new last run time")
	}

	// Tests folder
	lastRunTime, err = lastRun("test_data/")

	if err == nil {
		t.Errorf("Failed to detect target is a folder")
	}

	// Tests parsing of incomplete file
	lastRunTime, err = lastRun("test_data/malformed.conf")

	if err == nil {
		t.Errorf("Loaded a very malformed lastrun file")
	}

	// Tests parsing of a valid file
	lastRunTime, err = lastRun("test_data/lastrun")
	compareTo, tErr := time.Parse("2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05Z")

	if tErr != nil {
		t.Errorf("Failed to generate time for comparision")
	}

	if err != nil || lastRunTime != compareTo {
		t.Errorf("Failed to parse a valid lastrun")
	}

}

func TestSaveLastRun(t *testing.T) {
	// Tests saving to new file and verifies output
	testFile := uuid.New().String()
	timeStamp, tErr := time.Parse("2006-01-02T15:04:05Z07:00", "2019-08-08T3:01:35Z")

	if tErr != nil {
		t.Errorf("Setup failed")
	}

	err := saveRun(timeStamp, "/tmp/"+testFile)

	if err != nil {
		t.Errorf("Failed to save last run to file")
	}

	data, err := ioutil.ReadFile("/tmp/" + testFile)
	if err != nil {
		log.Fatal(err)
	}

	readTimeStamp, err := time.Parse("2006-01-02T15:04:05Z07:00", string(data))

	if err != nil || readTimeStamp != timeStamp {
		t.Errorf("Failed to save last run with right timestamp")
	}

	// Tests overwriting file and verifies output

	timeStamp, tErr = time.Parse("2006-01-02T15:04:05Z07:00", "2019-03-08T12:30:35Z")

	if tErr != nil {
		t.Errorf("Setup failed")
	}

	err = saveRun(timeStamp, "/tmp/"+testFile)

	if err != nil {
		t.Errorf("Failed to overwrite last run file")
	}

	data, err = ioutil.ReadFile("/tmp/" + testFile)
	if err != nil {
		log.Fatal(err)
	}

	readTimeStamp, err = time.Parse("2006-01-02T15:04:05Z07:00", string(data))

	if err != nil || readTimeStamp != timeStamp {
		t.Errorf("Failed to overwrite last run with right timestamp")
	}
}

func TestDirLister(t *testing.T) {
	// Tests directory with no log files
	files, err := findLogFiles("test_data/", "fail2ban")

	if files != nil || err == nil {
		t.Errorf("Shouldn't have found any log files")
	}

	// Tests looking into a file instead of a dir
	files, err = findLogFiles("test_data/rtest.log", "fail2ban")

	if files != nil || err == nil {
		t.Errorf("Found files when a filepath has been entered, instead of a directory....")
	}

	// Tests "normal" log rotation
	files, err = findLogFiles("test_data/logs1", "fail2ban")

	if err != nil || files[0] != "fail2ban.log" || files[1] != "fail2ban.log.1" || files[2] != "fail2ban.log.2.gz" {
		fmt.Println(files)
		t.Errorf("Normal log rotation method ordering broken")
	}

	// Tests "date" log rotation
	files, err = findLogFiles("test_data/logs2", "fail2ban")

	if err != nil || files[0] != "fail2ban.log" || files[1] != "fail2ban.log-20200531" || files[2] != "fail2ban.log-20200517" {
		fmt.Println(files)
		t.Errorf("Date log rotation method ordering broken")
	}
}

func TestProcessBans(t *testing.T) {
	// Setup
	testFile := uuid.New().String()
	timeStamp, tErr := time.Parse("2006-01-02T15:04:05Z07:00", "2005-08-08T3:01:35Z")
	err := saveRun(timeStamp, "/tmp/"+testFile)

	if err != nil || tErr != nil {
		t.Errorf("Error setting up")
	}

	// Tests empty folder
	status, err := processBans("test_data/logs3/", "fail2ban", "test", 1, []string{"jupyter"}, "testing", "/tmp/"+testFile)

	if err == nil || status != 0 {
		t.Errorf("Shouldn't have found any bans...")
	}

	// Tests response for no bans
	status, err = processBans("test_data/logs4/", "fail2ban", "test", 1, []string{"jupyter"}, "testing", "/tmp/"+testFile)

	if err == nil && status != 1 {
		t.Errorf("Service filter has failed or the response to no bans is invalid")
	}

	// Setup
	testFile = uuid.New().String()
	timeStamp, tErr = time.Parse("2006-01-02T15:04:05Z07:00", "2018-08-11T19:04:08Z")
	err = saveRun(timeStamp, "/tmp/"+testFile)

	if err != nil || tErr != nil {
		t.Errorf("Error setting up")
	}

	// Tests everything else including submission
	status, err = processBans("test_data/logs5/", "fail2ban", "test", 1, []string{"jupyter"}, "testing", "/tmp/"+testFile)

	if err != nil || status != 2 {
		t.Errorf("Something went wrong - could be anything... ")
	}

}
