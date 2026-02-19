package certificatetransparency

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	errCreatingClient    = errors.New("failed to create JSON client")
	errFetchingSTHFailed = errors.New("failed to fetch STH")
	userAgent            = getDefaultUserAgent()
)

// getDefaultUserAgent returns the default user agent string.
func getDefaultUserAgent() string {
	return fmt.Sprintf("Certstream Server v%s (github.com/pki-tools/certstream-server-go)", config.Version)
}

// loadCustomUserAgent checks for a 'certstream-ua' file in the executable's directory
// and loads a custom user agent if present. Returns true if a custom UA was loaded.
func loadCustomUserAgent() bool {
	// Get the executable path
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("Could not determine executable path: %s\n", err)
		return false
	}

	// Get the directory containing the executable
	exeDir := filepath.Dir(exePath)
	uaFilePath := filepath.Join(exeDir, "certstream-ua")

	// Check if the file exists
	if _, err := os.Stat(uaFilePath); os.IsNotExist(err) {
		// File doesn't exist, use default
		return false
	}

	// Read the file
	content, err := os.ReadFile(uaFilePath)
	if err != nil {
		log.Printf("Error reading certstream-ua file: %s\n", err)
		return false
	}

	// Trim whitespace and check if non-empty
	customUA := strings.TrimSpace(string(content))
	if customUA == "" {
		log.Println("certstream-ua file is empty, using default user agent")
		return false
	}

	// Update the global userAgent variable
	userAgent = customUA
	log.Printf("Loaded custom user agent from certstream-ua: %s\n", customUA)
	return true
}

// Watcher describes a component that watches for new certificates in a CT log.
type Watcher struct {
	workers       []*worker
	tiledWorkers  []*tiledWorker
	workersMu     sync.RWMutex
	wg            sync.WaitGroup
	context       context.Context
	certChan      chan models.Entry
	cancelFunc    context.CancelFunc
}

// NewWatcher creates a new Watcher.
func NewWatcher(certChan chan models.Entry) *Watcher {
	return &Watcher{
		certChan: certChan,
	}
}

// Start starts the watcher. This method is blocking.
func (w *Watcher) Start() {
	w.context, w.cancelFunc = context.WithCancel(context.Background())

	// Load custom user agent from file if present
	loadCustomUserAgent()

	// Create new certChan if it doesn't exist yet
	if w.certChan == nil {
		w.certChan = make(chan models.Entry, 5000)
	}

	if config.AppConfig.General.Recovery.Enabled {
		ctIndexFilePath, err := filepath.Abs(config.AppConfig.General.Recovery.CTIndexFile)
		if err != nil {
			log.Printf("Error getting absolute path for CT index file: '%s', %s\n", config.AppConfig.General.Recovery.CTIndexFile, err)
			return
		}
		// Load Saved CT Indexes
		metrics.LoadCTIndex(ctIndexFilePath)
		// Save CTIndexes at regular intervals
		go metrics.SaveCertIndexesAtInterval(time.Second*30, ctIndexFilePath) // save indexes every X seconds
	}

	// initialize the watcher with currently available logs
	w.updateLogs()

	log.Println("Started CT watcher")
	go certHandler(w.certChan)
	go w.watchNewLogs()

	// Wait for all workers to finish
	w.wg.Wait()
	close(w.certChan)
}

// watchNewLogs monitors the ct log list for new logs and starts a worker for each new log found.
// This method is blocking. It can be stopped by cancelling the context.
func (w *Watcher) watchNewLogs() {
	// Check for new logs and CCADB once every 6 hours
	ticker := time.NewTicker(6 * time.Hour)
	for {
		select {
		case <-ticker.C:
			w.updateLogs()
		case <-w.context.Done():
			ticker.Stop()
			return
		}
	}
}

// updateLogs checks the transparency log list for new logs and adds new workers for those to the watcher.
func (w *Watcher) updateLogs() {
	// Download and parse CCADB data for CA ownership
	ccadbURL := "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4"
	log.Println("Downloading CCADB data for CA ownership...")
	caOwners, err := DownloadAndParseCSV(ccadbURL, 18, 0, true)
	if err != nil {
		log.Printf("Failed to download CCADB data: %v (keeping existing CA owner data)\n", err)
	} else if len(caOwners) == 0 {
		log.Printf("CCADB data is empty or invalid (keeping existing CA owner data)\n")
	} else {
		// Only update if we got valid data with at least some entries
		oldCount := len(CAOwners)
		CAOwners = caOwners
		log.Printf("Successfully loaded %d CA owner mappings from CCADB (previous: %d)\n", len(CAOwners), oldCount)
	}

	// Get a list of urls of all CT logs
	logList, err := getAllLogs()
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Checking for new ct logs...")

	// Track all URLs that should be monitored after reconciliation
	monitoredURLs := make(map[string]struct{})
	newCTs := 0

	w.workersMu.Lock()
	defer w.workersMu.Unlock()

	for _, operator := range logList.Operators {
		// Iterate over each log of the operator
		for _, transparencyLog := range operator.Logs {
			url := transparencyLog.URL
			desc := transparencyLog.Description
			normURL := normalizeCtlogURL(url)

			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", normURL)
				continue
			}

			monitoredURLs[normURL] = struct{}{}
			if w.addLogIfNew(operator.Name, desc, url) {
				newCTs++
			}
		}
	}

	log.Printf("New ct logs found: %d\n", newCTs)

	// Process tiled logs
	newTiledCTs := 0
	for _, operator := range logList.Operators {
		// Iterate over each tiled log of the operator
		for _, tiledLog := range operator.TiledLogs {
			monitoringURL := tiledLog.MonitoringURL
			desc := tiledLog.Description
			normURL := normalizeCtlogURL(monitoringURL)

			if tiledLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired tiled CT log: %s\n", normURL)
				continue
			}

			monitoredURLs[normURL] = struct{}{}
			if w.addTiledLogIfNew(operator.Name, desc, tiledLog) {
				newTiledCTs++
			}
		}
	}

	log.Printf("New tiled ct logs found: %d\n", newTiledCTs)

	// Optionally stop workers for logs not in the monitoredURLs set
	if *config.AppConfig.General.DropOldLogs {
		removed := 0
		for _, ctWorker := range w.workers {
			normURL := normalizeCtlogURL(ctWorker.ctURL)
			if _, ok := monitoredURLs[normURL]; !ok {
				log.Printf("Stopping worker. CT URL not found in LogList or retired: '%s'\n", ctWorker.ctURL)
				ctWorker.stop()
				removed++
			}
		}

		// Also stop tiled workers not in the list
		for _, tiledWorker := range w.tiledWorkers {
			normURL := normalizeCtlogURL(tiledWorker.monitoringURL)
			if _, ok := monitoredURLs[normURL]; !ok {
				log.Printf("Stopping tiled worker. CT URL not found in LogList or retired: '%s'\n", tiledWorker.monitoringURL)
				tiledWorker.stop()
				removed++
			}
		}
		log.Printf("Removed ct logs: %d\n", removed)
	}

	log.Printf("Currently monitored ct logs: %d (regular) + %d (tiled) = %d total\n", len(w.workers), len(w.tiledWorkers), len(w.workers)+len(w.tiledWorkers))
}

// addLogIfNew checks if a log is already being watched and adds it if not.
// Returns true if a new log was added, false otherwise.
func (w *Watcher) addLogIfNew(operatorName, description, url string) bool {
	normURL := normalizeCtlogURL(url)

	// Check if the log is already being watched
	for _, ctWorker := range w.workers {
		workerURL := normalizeCtlogURL(ctWorker.ctURL)
		if workerURL == normURL {
			return false
		}
	}

	// Log is not being watched, so add it
	w.wg.Add(1)

	lastCTIndex := metrics.GetCTIndex(normURL)
	ctWorker := worker{
		name:         description,
		operatorName: operatorName,
		ctURL:        url,
		entryChan:    w.certChan,
		ctIndex:      lastCTIndex,
	}
	w.workers = append(w.workers, &ctWorker)
	metrics.Init(operatorName, normURL)

	// Start a goroutine for each worker
	go func() {
		defer w.wg.Done()
		ctWorker.startDownloadingCerts(w.context)
		w.discardWorker(&ctWorker)
	}()

	return true
}

// discardWorker removes a worker from the watcher's list of workers.
// This needs to be done when a worker stops.
func (w *Watcher) discardWorker(worker *worker) {
	log.Println("Removing worker for CT log:", worker.ctURL)

	w.workersMu.Lock()
	defer w.workersMu.Unlock()

	for i, wo := range w.workers {
		if wo == worker {
			w.workers = append(w.workers[:i], w.workers[i+1:]...)
			return
		}
	}
}

// addTiledLogIfNew checks if a tiled log is already being watched and adds it if not.
// Returns true if a new tiled log was added, false otherwise.
func (w *Watcher) addTiledLogIfNew(operatorName, description string, tiledLog *loglist3.TiledLog) bool {
	normURL := normalizeCtlogURL(tiledLog.MonitoringURL)

	// Check if the tiled log is already being watched
	for _, tiledWorker := range w.tiledWorkers {
		workerURL := normalizeCtlogURL(tiledWorker.monitoringURL)
		if workerURL == normURL {
			return false
		}
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(tiledLog.Key)
	if err != nil {
		log.Printf("Failed to parse public key for tiled log '%s': %s\n", tiledLog.MonitoringURL, err)
		return false
	}

	// Tiled log is not being watched, so add it
	w.wg.Add(1)

	lastCTIndex := int64(metrics.GetCTIndex(normURL))
	tiledWorker := tiledWorker{
		name:          description,
		operatorName:  operatorName,
		monitoringURL: tiledLog.MonitoringURL,
		publicKey:     publicKey,
		entryChan:     w.certChan,
		ctIndex:       lastCTIndex,
	}
	w.tiledWorkers = append(w.tiledWorkers, &tiledWorker)
	metrics.Init(operatorName, normURL)

	// Start a goroutine for each tiled worker
	go func() {
		defer w.wg.Done()
		tiledWorker.startDownloadingCerts(w.context)
		w.discardTiledWorker(&tiledWorker)
	}()

	return true
}

// discardTiledWorker removes a tiled worker from the watcher's list of tiled workers.
// This needs to be done when a tiled worker stops.
func (w *Watcher) discardTiledWorker(worker *tiledWorker) {
	log.Println("Removing tiled worker for CT log:", worker.monitoringURL)

	w.workersMu.Lock()
	defer w.workersMu.Unlock()

	for i, wo := range w.tiledWorkers {
		if wo == worker {
			w.tiledWorkers = append(w.tiledWorkers[:i], w.tiledWorkers[i+1:]...)
			return
		}
	}
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	log.Printf("Stopping watcher\n")

	if config.AppConfig.General.Recovery.Enabled {
		// Store current CT Indexes before shutting down
		filePath := config.AppConfig.General.Recovery.CTIndexFile
		metrics.SaveCertIndexes(filePath)
	}

	w.cancelFunc()
}

// CreateIndexFile creates a ct_index.json file based on the current STHs of all availble logs.
func (w *Watcher) CreateIndexFile(filePath string) error {
	logs, err := getAllLogs()
	if err != nil {
		return err
	}

	w.context, w.cancelFunc = context.WithCancel(context.Background())
	log.Println("Fetching current STH for all logs...")
	for _, operator := range logs.Operators {
		// Iterate over each log of the operator
		for _, transparencyLog := range operator.Logs {
			// Check if the log is already being watched
			metrics.Init(operator.Name, normalizeCtlogURL(transparencyLog.URL))
			log.Println("Fetching STH for", normalizeCtlogURL(transparencyLog.URL))

			hc := http.Client{Timeout: 5 * time.Second}
			jsonClient, e := client.New(transparencyLog.URL, &hc, jsonclient.Options{UserAgent: userAgent})
			if e != nil {
				log.Printf("Error creating JSON client: %s\n", e)
				continue
			}

			sth, getSTHerr := jsonClient.GetSTH(w.context)
			if getSTHerr != nil {
				// TODO this can happen due to a 429 error. We should retry the request
				log.Printf("Could not get STH for '%s': %s\n", transparencyLog.URL, getSTHerr)
				continue
			}

			metrics.SetCTIndex(normalizeCtlogURL(transparencyLog.URL), sth.TreeSize)
		}
	}
	w.cancelFunc()

	metrics.SaveCertIndexes(filePath)
	log.Println("Index file saved to", filePath)

	return nil
}

// A worker processes a single CT log.
type worker struct {
	name         string
	operatorName string
	ctURL        string
	entryChan    chan models.Entry
	ctIndex      uint64
	mu           sync.Mutex
	running      bool
	cancel       context.CancelFunc
}

// startDownloadingCerts starts downloading certificates from the CT log. This method is blocking.
func (w *worker) startDownloadingCerts(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	// Normalize CT URL. We remove trailing slashes and prepend "https://" if it's not already there.
	w.ctURL = strings.TrimRight(w.ctURL, "/")
	if !strings.HasPrefix(w.ctURL, "https://") && !strings.HasPrefix(w.ctURL, "http://") {
		w.ctURL = "https://" + w.ctURL
	}

	log.Printf("Initializing worker for CT log: %s\n", w.ctURL)
	defer log.Printf("Stopping worker for CT log: %s\n", w.ctURL)

	w.mu.Lock()
	if w.running {
		log.Printf("Worker for '%s' already running\n", w.ctURL)
		w.mu.Unlock()

		return
	}

	w.running = true
	defer func() { w.running = false }()
	w.mu.Unlock()

	for {
		log.Printf("Starting worker for CT log: %s\n", w.ctURL)
		workerErr := w.runWorker(ctx)
		if workerErr != nil {
			if errors.Is(workerErr, errFetchingSTHFailed) {
				// TODO this could happen due to a 429 error. We should retry the request
				log.Printf("Worker for '%s' failed - could not fetch STH\n", w.ctURL)
				return
			} else if errors.Is(workerErr, errCreatingClient) {
				log.Printf("Worker for '%s' failed - could not create client\n", w.ctURL)
				return
			} else if strings.Contains(workerErr.Error(), "no such host") {
				log.Printf("Worker for '%s' failed to resolve host: %s\n", w.ctURL, workerErr)
				return
			}

			log.Printf("Worker for '%s' failed with unexpected error: %s\n", w.ctURL, workerErr)
		}

		// Check if the context was cancelled
		select {
		case <-ctx.Done():
			log.Printf("Context was cancelled; Stopping worker for '%s'\n", w.ctURL)

			return
		default:
			log.Printf("Worker for '%s' sleeping for 5 seconds due to error\n", w.ctURL)
			time.Sleep(5 * time.Second)
			log.Printf("Restarting worker for '%s'\n", w.ctURL)

			continue
		}
	}
}

func (w *worker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cancel()
}

// runWorker runs a single worker for a single CT log. This method is blocking.
func (w *worker) runWorker(ctx context.Context) error {
	hc := http.Client{Timeout: 30 * time.Second}
	jsonClient, e := client.New(w.ctURL, &hc, jsonclient.Options{UserAgent: userAgent})
	if e != nil {
		log.Printf("Error creating JSON client: %s\n", e)
		return errCreatingClient
	}

	// If recovery is enabled, we start at the saved index. Otherwise, we start at the latest STH.
	recoveryEnabled := config.AppConfig.General.Recovery.Enabled
	if !recoveryEnabled {
		sth, getSTHerr := jsonClient.GetSTH(ctx)
		if getSTHerr != nil {
			// TODO this can happen due to a 429 error. We should retry the request
			log.Printf("Could not get STH for '%s': %s\n", w.ctURL, getSTHerr)
			return errFetchingSTHFailed
		}
		// Start at the latest STH to skip all the past certificates
		w.ctIndex = sth.TreeSize
	}

	certScanner := scanner.NewScanner(jsonClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     100,
			ParallelFetch: 1,
			StartIndex:    int64(w.ctIndex),
			Continuous:    true,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  config.AppConfig.General.BufferSizes.CTLog,
	})

	scanErr := certScanner.Scan(ctx, w.foundCertCallback, w.foundPrecertCallback)
	if scanErr != nil {
		log.Println("Scan error: ", scanErr)
		return scanErr
	}

	log.Printf("Exiting worker %s without error!\n", w.ctURL)

	return nil
}

// foundCertCallback is the callback that handles cases where new regular certs are found.
func (w *worker) foundCertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "X509LogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&processedCerts, 1)
}

// foundPrecertCallback is the callback that handles cases where new precerts are found.
func (w *worker) foundPrecertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "PrecertLogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&processedPrecerts, 1)
}

// certHandler takes the entries out of the entryChan channel and broadcasts them to all clients.
// Only a single instance of the certHandler runs per certstream server.
func certHandler(entryChan chan models.Entry) {
	var processed int64

	for {
		entry := <-entryChan
		processed++

		if processed%1000 == 0 {
			log.Printf("Processed %d entries | Queue length: %d\n", processed, len(entryChan))
			// Every thousandth entry, we store one certificate as example
			web.SetExampleCert(entry)
		}

		// Run json encoding in the background and send the result to the clients.
		web.ClientHandler.Broadcast <- entry

		// Update metrics
		url := entry.Data.Source.NormalizedURL
		operator := entry.Data.Source.Operator
		index := entry.Data.CertIndex

		metrics.Inc(operator, url, index)
	}
}

// getGoogleLogList fetches the list of all CT logs from Google Chromes CT LogList.
func getGoogleLogList() (loglist3.LogList, error) {
	// Download the list of all logs from ctLogInfo and decode json
	resp, err := http.Get(loglist3.LogListURL)
	if err != nil {
		return loglist3.LogList{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loglist3.LogList{}, errors.New("failed to download loglist")
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Panic(readErr)
	}

	allLogs, parseErr := loglist3.NewFromJSON(bodyBytes)
	if parseErr != nil {
		return loglist3.LogList{}, parseErr
	}

	return *allLogs, nil
}

// getAllLogs returns a list of all CT logs.
func getAllLogs() (loglist3.LogList, error) {
	var allLogs loglist3.LogList
	var err error

	// Ability to disable default logs, if the user only wants to monitor custom logs.
	if !config.AppConfig.General.DisableDefaultLogs {
		allLogs, err = getGoogleLogList()
		if err != nil {
			log.Printf("Error fetching log list from Google: %s\n", err)
			return loglist3.LogList{}, fmt.Errorf("failed to fetch log list from Google: %w", err)
		}
	}

	// Add manually added logs from config to the allLogs list
	if config.AppConfig.General.AdditionalLogs == nil {
		return allLogs, nil
	}

	for _, additionalLog := range config.AppConfig.General.AdditionalLogs {
		customLog := loglist3.Log{
			URL:         additionalLog.URL,
			Description: additionalLog.Description,
		}

		operatorFound := false
		for _, operator := range allLogs.Operators {
			if operator.Name == additionalLog.Operator {
				// TODO Check if the log is already in the list
				operator.Logs = append(operator.Logs, &customLog)
				operatorFound = true

				break
			}
		}

		if !operatorFound {
			newOperator := loglist3.Operator{
				Name: additionalLog.Operator,
				Logs: []*loglist3.Log{&customLog},
			}
			allLogs.Operators = append(allLogs.Operators, &newOperator)
		}
	}

	return allLogs, nil
}

func normalizeCtlogURL(input string) string {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")

	return input
}

// DownloadAndParseCSV downloads a CSV file from the given URL and parses it into a map.
// keyColIndex is the column index for the map key, valueColIndex is the column index for the map value.
// If skipHeader is true, the first row is skipped.
// The function retries up to 3 times with exponential backoff on network failures.
func DownloadAndParseCSV(url string, keyColIndex, valueColIndex int, skipHeader bool) (map[string]string, error) {
	var resp *http.Response
	var err error

	// Retry logic with exponential backoff
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 2 * time.Second
			log.Printf("Retrying CCADB download in %v (attempt %d/%d)\n", backoff, attempt+1, maxRetries)
			time.Sleep(backoff)
		}

		resp, err = http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to download CSV after %d attempts: %w", maxRetries, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download CSV: HTTP %d", resp.StatusCode)
	}

	// Parse CSV
	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	// Validate CSV has minimum expected data
	minRecords := 10 // CCADB should have hundreds of CAs, so 10 is a very low bar
	if len(records) < minRecords {
		return nil, fmt.Errorf("CSV has too few records (%d), expected at least %d - possible format change or corrupted download", len(records), minRecords)
	}

	// Validate CSV has expected columns (we need at least keyColIndex+1 columns)
	if len(records) > 0 && len(records[0]) <= keyColIndex {
		return nil, fmt.Errorf("CSV missing expected columns (has %d columns, need at least %d) - possible format change", len(records[0]), keyColIndex+1)
	}

	result := make(map[string]string)
	startRow := 0
	if skipHeader && len(records) > 0 {
		startRow = 1
	}

	validEntries := 0
	for i := startRow; i < len(records); i++ {
		record := records[i]
		if len(record) <= keyColIndex {
			continue
		}

		// For CCADB, the key is the base64-decoded SKI from column 18
		// and the value is the CA Owner from column 0
		key := record[keyColIndex]
		var value string
		if valueColIndex >= 0 && len(record) > valueColIndex {
			value = record[valueColIndex]
		} else if valueColIndex == 0 {
			value = record[0]
		}

		// Decode base64 key (SKI) and convert to lowercase hex
		if key != "" {
			decoded, err := base64.StdEncoding.DecodeString(key)
			if err == nil {
				hexKey := fmt.Sprintf("%x", decoded)
				result[hexKey] = value
				validEntries++
			}
		}
	}

	// Ensure we parsed at least some valid entries
	if validEntries == 0 {
		return nil, fmt.Errorf("no valid entries parsed from CSV - possible format change or data issue")
	}

	return result, nil
}
