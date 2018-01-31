//
// Spin up an HTTP server on 8080 and listen for "/hash" POST requests with body: password=somepassword
// Return a 'token' immediately that can be used 5 seconds later to retrieve the SHA512 hashed, base64 encoded password
// Provide a stats endpoint for statistics
// Handle graceful shutdown of the service
//
// Implementation of an Interview Coding Assignment
//
// Copyright 2018, David Ferrero, All Rights Reserved.
//

package main

import (
    "context"
    "crypto/sha512"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"
)

/////////////////////////////////////////////////////////////////////
// package variables
/////////////////////////////////////////////////////////////////////

// true after http.Server.Shutdown(ctx) returns indicating all connections have finished
var shutdownComplete = false

// map with key=token, value = hashed passwords
var hashedPasswords = make(map[string] string)

// keep track of pending hashing requests so /shutdown request will wait for any outstanding hashing requests
var pendingHashingTasks = make(map[string] int64)
var pendingHashingTasksMutex sync.Mutex

// keep running total of time spent on hash requests
var totalTimeSpent = int64(0)
var totalTimeSpentMutex sync.Mutex
/////////////////////////////////////////////////////////////////////

// struct for Stats
type HashStats struct {
    Total int64
    Average int64
}


func main() {

    // install request handler functions
    http.HandleFunc("/hash", hashPostHandler)
    http.HandleFunc("/hash/", hashGetHandler)
    http.HandleFunc("/stats", statsGetHandler)
    http.HandleFunc("/shutdown", shutdownHandler)

    // start listening for requests
    // this will not return until an error or /shutdown request is received
    log.Println("Listening for requests on 8080\n")
    listenAndServeError := http.ListenAndServe(":8080", nil)

    // wait for up to 10 seconds for a graceful Shutdown
    // graceful Shutdown allows all http requests to complete
    // and all hashing tasks to complete
    var ErrServerClosed = errors.New("http: Server closed")
    if listenAndServeError.Error() == ErrServerClosed.Error() {
        for wait := 0; wait < 10; wait +=1 {
            // if shutdownComplete AND pendingHashingTasks is empty
            pendingHashingTasksMutex.Lock()
            pendingHashingTasksRemaining := len(pendingHashingTasks)
            pendingHashingTasksMutex.Unlock()
            if shutdownComplete && pendingHashingTasksRemaining == 0 {
                break
            }

            time.Sleep(1000 * time.Millisecond)
            fmt.Print(".")
        }
    }

    fmt.Print("\n")
    log.Fatal(listenAndServeError)
}

//
// hashPostHandler to accept password in POST body
// return a 'token' immediately that can be used 5 seconds later to retrieve the SHA512 hashed, base64 encoded password
// using the /hash/<token> endpoint
//
func hashPostHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("/hash POST request received")

    processStartTime := time.Now()

    // ensure request is POST method
    if r.Method != http.MethodPost { // Only POST is supported
        http.Error(w, "405 Method Not Allowed", 405)
        return
    }

    // check for request body and password
    password := passwordFromRequest(r.Body)
    if password == "" {
        http.Error(w, "400 Bad Request", 400)
        return
    }

    // generate and return a token for this request
    token := generateHashToken()
    w.Write([]byte(token))

    // per interview requirements, schedule actual password hashing 5 seconds from now
    go func() {
        pendingHashingTasksMutex.Lock()
        pendingHashingTasks[token] = time.Now().Unix()
        pendingHashingTasksMutex.Unlock()
        time.Sleep(1000 * 5 * time.Millisecond)

        // SHA512 hash the password, then base64
        base64HashedPassword := base64_hash(password)

        // remove, hashing task completed
        pendingHashingTasksMutex.Lock()
        delete(pendingHashingTasks, token)
        pendingHashingTasksMutex.Unlock()

        processEndTime := time.Now()
        duration := processEndTime.Sub(processStartTime)

        //////////////////////////////////////////////
        // update totalTimeSpent in a thread-safe manner
        totalTimeSpentMutex.Lock()

        hashedPasswords[token] = base64HashedPassword // store token with hashed password
        totalTimeSpent += duration.Nanoseconds()

        totalTimeSpentMutex.Unlock()
        //////////////////////////////////////////////
    }()
}

//
// hashGetHandler to accept 'token' for a previously hashed password
// return SHA512 hashed, base64 encoded password or 404 error if not found
// if token parameter is not present return a 400 Bad Request error.
//
func hashGetHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("/hash/<token> GET request received")

    // ensure request is GET method
    if r.Method != http.MethodGet { // Only GET is supported
        http.Error(w, "405 Method Not Allowed", 405)
        return
    }

    // ensure token was provided in the request
    token := tokenFromHashGetRequestURL(r.URL)
    if token == "" {
        http.Error(w, "400 Bad Request", 400)
        return
    }

    totalTimeSpentMutex.Lock()
    base64HashedPassword := hashedPasswords[token]
    totalTimeSpentMutex.Unlock()

    if base64HashedPassword == "" { // result not yet available or not found
        http.Error(w, "404 Not Found", 404)
        return
    }

    // return the base64HashedPassword
    w.Write([]byte(base64HashedPassword))
}


//
// statsGetHandler
// return JSON structure with "total" number and "average" time in milliseconds for hash requests
//
func statsGetHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("/stats GET request received")

    // ensure request is GET method
    if r.Method != http.MethodGet { // Only GET is supported
        http.Error(w, "405 Method Not Allowed", 405)
        return
    }

    stats := computeStats()
    jsonBytes, err := json.Marshal(stats)
    if err != nil {
        http.Error(w, "500 Internal Server Error", 500)
        return
    }

    // set header to application/json format
    w.Header().Set("Content-Type", "application/json; charset=utf-8") // normal header
    w.WriteHeader(http.StatusOK)
    w.Write(jsonBytes)
}


//
// shutdownHandler to gracefully shutdown the server when all connections are idle
//
func shutdownHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("/shutdown request received")

    // lookup http.Server from request context
    ctx := r.Context()
    server := ctx.Value(http.ServerContextKey).(*http.Server)

    // send client a response to acknowledge the request
    w.Write([]byte("shutdown request received\n"))

    // avoid keeping request alive, thereby indefinitely delaying the shutdown process,
    // fork a goroutine task to perform the actual http.Server.Shutdown(ctx)
    go func() {
        log.Println("Waiting on active connections and pending tasks to finish")

        // use context.Background() instead of request's ctx
        // in order to delay Shutdown until all requests have finished
        server.Shutdown(context.Background())
        shutdownComplete = true
    }()
}

//
// read request body to ensure it's in the proper form
// password=somepassword
// Note: this function truncates the password length to 256
// Note: this function requires the password be at least 4 characters in length
//
func passwordFromRequest(body io.ReadCloser) string {
    minPwLen := 4
    argLen := len("password=")
    buf := make([]byte, 256+argLen) // truncate password to max length of 256

    // password=somepassword
    // must read at least "password="
    numRead, err := io.ReadAtLeast(body, buf, argLen)
    if err != nil && numRead < argLen+minPwLen {
        return ""
    }

    // check prefix of buff for "password="
    if string(buf[0:9]) != "password=" {
        return ""
    }

    return string(buf[9:numRead]) // everything after "password="
}


//
// given a hashGetRequest URL "/hash/<token>"
// return the last item in the path <token> or empty string if "hash/" not found
//
func tokenFromHashGetRequestURL(url *url.URL) string {
    uriPath := url.RequestURI()
    pathIndex := strings.LastIndex(uriPath, "hash/")
    if pathIndex == -1 { // not found
        return ""
    }

    // return everything in uri after "hash/"
    return uriPath[pathIndex+len("hash/"):]
}


//
// Given an input string,
// hash the input using SHA512,
// return the base64 string of the hash
//
func base64_hash(s string) string {
    data := []byte(s)
    sha512Checksum := sha512.Sum512(data)
    return base64.StdEncoding.EncodeToString(sha512Checksum[:])
}


//
// generate a token identifier for use by hash endpoints
// TODO: for a secure token, use a GUID generator instead
//
func generateHashToken() string {
    time := time.Now()
    return base64_hash(time.String())
}


//
// compute the HashStats
//
func computeStats() HashStats {
    //////////////////////////////////////////////
    // read totalTimeSpent in a thread-safe manner
    totalTimeSpentMutex.Lock()

    var averageHashTimeInNanoseconds int64 = 0
    totalHashed := int64(len(hashedPasswords))
    if totalHashed > 0 {
        averageHashTimeInNanoseconds = totalTimeSpent / totalHashed
    }

    totalTimeSpentMutex.Unlock()
    //////////////////////////////////////////////

    avgHashTimeMilliseconds := averageHashTimeInNanoseconds / int64(1000 * 1000)
    return HashStats { Total: totalHashed, Average: avgHashTimeMilliseconds }
}
