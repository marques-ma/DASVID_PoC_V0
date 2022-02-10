package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"net"
	"context"
	"time"
	// "strconv"


	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	
	// dasvid lib test
	dasvid "github.com/marco-developer/dasvid/poclib"

	// To sig. validation 
	_ "crypto/sha256"
	
	"github.com/gorilla/sessions"
	// Okta
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
	
)

const (
	// Workload API socket path
	socketPath   	= "unix:///tmp/spire-agent/public/api.sock"
	HostIP 			= "192.168.0.5:8080"
	AssertingwlIP 	= "192.168.0.5:8443" 
	TargetwlIP		= "192.168.0.5:8444"
)

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

type PocData struct {
	AppURI			string
	Profile         map[string]string
	IsAuthenticated bool
	HaveDASVID		bool
	AccessToken     string
	PublicKey		string
	SigValidation 	string
	ExpValidation 	string
	RetClaims		map[string]interface{}
	DASVIDToken		string
	DASVIDClaims 	map[string]interface{}
	DasvidExpValidation string
	Returnmsg		string
	Balance			int
		
}

type Contents struct {
	OauthSigValidation 			*bool `json:",omitempty"`
	OauthExpValidation 			*bool `json:",omitempty"`
	OauthExpRemainingTime		string `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
}

type Balancetemp struct {
	User						string `json:",omitempty"`
	Balance						int `json:",omitempty"`
	Returnmsg					string `json:",omitempty"`

}

var temp Contents
var oktaclaims map[string]interface{}
var dasvidclaims map[string]interface{}
var Data PocData

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GetOutboundIP(port string) string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
    return uri
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func main() {

	// sessionStore.Options.MaxAge = 180
	oktaUtils.ParseEnvironment()

	// Retrieve local IP
	uri := GetOutboundIP(":8080")

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/callback", AuthCodeCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)

	http.HandleFunc("/account", AccountHandler)
	http.HandleFunc("/get_balance", CheckbalanceHandler)
	http.HandleFunc("/deposit", DepositHandler)

	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	log.Print("Subject workload starting at ", uri)
	err := http.ListenAndServe(uri, nil)
	if err != nil {
		log.Printf("the Subject workload HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	
	Data = PocData{
		AppURI:			 HostIP,
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
		AccessToken:	 strAT,
	}

	
	tpl.ExecuteTemplate(w, "home.gohtml", Data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Login")

	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20
	
	// Retrieve local IP
	// Must be authorized in OKTA configuration.
	// Hard coded here to allow the redirection to subj wl container
	uri := "http://" + HostIP + "/callback"
	
	nonce, _ = oktaUtils.GenerateNonce()
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code") // code or token
	q.Add("response_mode", "query") // query or fragment
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", uri)
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Callback Handler")

	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		return
	}

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		log.Fatal(verificationError)
	}

	os.Setenv("oauthtoken", exchange.AccessToken)

	session.Values["id_token"] = exchange.IdToken
	session.Values["access_token"] = exchange.AccessToken
	session.Save(r, w)
	
	log.Printf("New login detected!")

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Profile Handler")

	Data = PocData{
		AppURI:			 HostIP,
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		HaveDASVID:		 haveDASVID(),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", Data)
}

func AccountHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Account Handler")

	receivedDASVID := getdasvid(os.Getenv("oauthtoken"))
	err := json.Unmarshal([]byte(receivedDASVID), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	if (*temp.OauthSigValidation == false) || (*temp.OauthExpValidation == false) {

		returnmsg := "Oauth token validation error"

		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			Returnmsg: 				returnmsg,
		}

		log.Printf(returnmsg)
		tpl.ExecuteTemplate(w, "home.gohtml", Data)

	} else {

		os.Setenv("DASVIDToken", temp.DASVIDToken)

		dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))

		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDToken:			temp.DASVIDToken,
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			SigValidation: 			fmt.Sprintf("%v", temp.OauthSigValidation),
			ExpValidation:			fmt.Sprintf("%v", temp.OauthExpValidation),
		}

		tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}

func CheckbalanceHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Check Balance")
	
	var funds Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
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

	dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))

	endpoint := "https://"+TargetwlIP+"/get_balance?DASVID="+os.Getenv("DASVIDToken")

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", TargetwlIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {
		
		fmt.Println("Return msg error:", funds.Returnmsg)
		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			HaveDASVID:				haveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		tpl.ExecuteTemplate(w, "home.gohtml", Data)	
		
	} else {

		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			Balance:				funds.Balance,
		}

		tpl.ExecuteTemplate(w, "get_balance.gohtml", Data)	
	}
}

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Deposit Handler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var funds Balancetemp

	dasvidclaims := dasvid.ParseTokenClaims(os.Getenv("DASVIDToken"))

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
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

	endpoint := "https://"+TargetwlIP+"/deposit?DASVID="+os.Getenv("DASVIDToken")+"&deposit="+r.FormValue("deposit")

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", TargetwlIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// With dasvid, app can make a call to middle tier, asking for user funds.
	err = json.Unmarshal([]byte(body), &funds)
	if err != nil {
		fmt.Println("error:", err)
	}

	if funds.Returnmsg != "" {

		fmt.Println("Return msg error:", funds.Returnmsg)
		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			HaveDASVID:				haveDASVID(),
			Returnmsg:				funds.Returnmsg,
		}
		
		tpl.ExecuteTemplate(w, "home.gohtml", Data)	
		
	} else {

		Data = PocData{
			AppURI:					HostIP,
			Profile:         		getProfileData(r),
			IsAuthenticated: 		isAuthenticated(r),
			DASVIDClaims:			dasvidclaims,
			HaveDASVID:				haveDASVID(),
			Balance:				funds.Balance,
		}
		
		tpl.ExecuteTemplate(w, "account.gohtml", Data)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	delete(session.Values, "DASVIDToken")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {

	defer timeTrack(time.Now(), "Exchange OKTA Oauth code")

	// Retrieve local IP
	uri := "http://" + HostIP + "/callback"

	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", uri)

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func haveDASVID() bool {

	if os.Getenv("DASVIDToken") == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {


	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func verifyToken(t string) (*verifier.Jwt, error) {

	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func getdasvid(oauthtoken string) (string) {

	defer timeTrack(time.Now(), "Get DASVID")
	
	// Asserting workload will validate oauth token, so we dont need to do it here.
	// stablish mtls with asserting workload and call mint endpoint, passing oauth token 
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
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

	var endpoint string
	token := os.Getenv("oauthtoken")
	endpoint = "https://"+AssertingwlIP+"/mint?AccessToken="+token

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", AssertingwlIP, err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	return fmt.Sprintf("%s", body)
}