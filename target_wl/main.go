package main

import (
    "strconv"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "strings"

    "github.com/joomcode/errorx"
    //Database
    "database/sql"

    // SPIFFE
    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
    "github.com/spiffe/go-spiffe/v2/workloadapi"

    // dasvid lib
    dasvid "github.com/marco-developer/dasvid/poclib"
)

const (
    socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

type PocData struct {
    AccessToken             string `json:",omitempty"`
    PublicKey               string `json:",omitempty"`
    OauthSigValidation      *bool `json:",omitempty"`
    OauthExpValidation      *bool `json:",omitempty"`
    OauthExpRemainingTime   string `json:",omitempty"`
    OauthClaims             map[string]interface{} `json:",omitempty"`
    DASVIDToken             string `json:",omitempty"`
    DASVIDClaims            map[string]interface{} `json:",omitempty"`
    DasvidExpValidation     *bool `json:",omitempty"`
    DasvidExpRemainingTime  string `json:",omitempty"`
    DasvidSigValidation     *bool `json:",omitempty"`
 }


type Balance struct {
    User        string `json:",omitempty"`
    Balance     int `json:",omitempty"`
    Returnmsg   string `json:",omitempty"`

}

// Handle_error recieves an error and a message, and returns the decorated error
// On recieving a non nil error, the function calls a fatal exception and logs the error
func Handle_error(err error, message string) (errorx.Error){

    error := errorx.Cast(err)

    if (message != ""){
        errorx.Decorate(error, message)
    }

    if error != nil {
        log.Fatalf("Error: %+v", *error)
    }

    return *error
}

func main(){

    // creates empty context to recieve an incoming request
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    http.HandleFunc("/get_balance", get_balance)
    http.HandleFunc("/deposit", update_data)


    source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    Handle_error(err, "Unable to create X509 source")
    defer source.Close()

    // Allowed SPIFFE ID - Client must be from this trust domain
    clientID := spiffeid.RequireTrustDomainFromString("example.org")

    // Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
    tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    log.Printf("Start serving API...")
    err = server.ListenAndServeTLS("", "")
    Handle_error(err, "Error on serve")

}

// GetOutboundIP currently returns the local address at 8.8.8.8:80
func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    Handle_error(err, "")
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

// get_validation calls the "validate" endpoint on the asserting workload with the recieved "data" string
// and returns the result of the DASVID validation
func get_validation(data string) (PocData){

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    //getting assertingwl ip
    Iplocal := GetOutboundIP()
    StrIPlocal := fmt.Sprintf("%v", Iplocal)
    serverURL := StrIPlocal + ":8444"


    url_parts := []string{"https://", serverURL, "/validate?DASVID=", data}

    endpoint := strings.Join(url_parts, "")


    // Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
    source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    Handle_error(err, "Unable to create X509Source")
    defer source.Close()


    // Allowed SPIFFE ID
    serverID := spiffeid.RequireTrustDomainFromString("example.org")


    // Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
    tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }


    //sending request
    r, err := client.Get(endpoint)

    errorMsg := "Error connecting to " + serverURL
    Handle_error(err, errorMsg)


    defer r.Body.Close()
    body, err := ioutil.ReadAll(r.Body)
    Handle_error(err, "Unable to read body")


    var result PocData
    json.Unmarshal(body, &result)


    return result
}

// validate_dasvid uses the asserting workload "validate" endpoint to validate
// Exp and sign validation for the recieved "data" string
// The function returns false on failing any validation, along with an error specifying the invalid field(s)
func validate_dasvid(data string) (bool, error) {

    result := get_validation(data)

    //validating response
    if !(*result.DasvidExpValidation) && !(*result.DasvidSigValidation){

        return false, errors.New("DASIVD expired and with invalid signature")
    }

    if !(*result.DasvidExpValidation){

        return false, errors.New("DASVID expired")
    }

    if !(*result.DasvidSigValidation){

        return false, errors.New("Invalid DASVID signature")
    }

    return true, nil
}

// get_balance endpoint validates the DASVID with validate_dasvid()
// and returns the required data to caller
func get_balance(w http.ResponseWriter, r *http.Request){

    data := r.FormValue("DASVID")
    validate_result, err := validate_dasvid(data)

    if !(validate_result) {

        log.Fatalf("Invalid DA-SVID: %v", err)
        json.NewEncoder(w).Encode(err)
        return
    }


    //in this example we will consider that only "web" subjects will be able request data
    dasvid_claims := dasvid.ParseTokenClaims(data)
    if dasvid_claims["sub"].(string) != "web"{

        log.Printf("Unauthorized subject workload!")
        json.NewEncoder(w).Encode("Unauthorized subject workload")
        return
    }


    var db *sql.DB

    db, err = sql.Open("sqlite3", "./balances.db")
    Handle_error(err, "Unable to open database balances.db")
    defer db.Close()


    var response Balance
    user := r.FormValue("User")

    //query database for account id
    query := "select " + user + " from balances;"

    //get database rows
    rows, err := db.Query(query)
    Handle_error(err, "Unable to query database")
    defer rows.Close()


    for rows.Next() {

        err = rows.Scan(&response.User, &response.Balance)
        response.Returnmsg = err.Error()
        Handle_error(err, "Unable do read rows")
    }
    log.Println("Read %v with balance %v from database", response.User, response.Balance)


    json.NewEncoder(w).Encode(response)
}

// update_data endpoint validates the DASVID with validate_dasvid()
// and updates the balance database
func update_data(w http.ResponseWriter, r *http.Request){

    data := r.FormValue("DASVID")
    validate_result, err := validate_dasvid(data)

    if !(validate_result) {

        log.Fatalf("Invalid DA-SVID: %v", err)
        json.NewEncoder(w).Encode(err)
        return
    }


    //in this example we will consider that only "web" subjects will be able request data
    dasvid_claims := dasvid.ParseTokenClaims(data)
    if dasvid_claims["sub"].(string) != "web"{

        log.Printf("Unauthorized subject workload!")
        json.NewEncoder(w).Encode("Unauthorized subject workload")
        return
    }


    var db *sql.DB

    db, err = sql.Open("sqlite3", "./balances.db")
    Handle_error(err, "Unable to open database balances.db")
    defer db.Close()

    var response Balance
    user := r.FormValue("User")
    added_balance := r.FormValue("Balance")

    //query database for account id
    query := "select " + user + " from balances;"

    //get database rows
    rows, err := db.Query(query)
    Handle_error(err, "Unable to query database")
    defer rows.Close()

    var user_data Balance
    for rows.Next() {

        err = rows.Scan(&user_data.User, &user_data.Balance)
        user_data.Returnmsg = err.Error()
        Handle_error(err, "Unable do read rows")
    }

    old_balance := user_data.Balance
    int_added_balance, err := strconv.Atoi(added_balance)
    Handle_error(err, "")

    new_balance := strconv.Itoa(old_balance + int_added_balance)
    
    query = "update balances SET balance=" + new_balance + " where User=" + user
    _, err = db.Exec(query)
    Handle_error(err, "Unable do update database")


    json.NewEncoder(w).Encode(response)

}
