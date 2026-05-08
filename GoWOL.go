package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"gopkg.in/yaml.v3"
)

const configPath = "./config.yaml"

var templates = template.Must(template.ParseFiles("template/UsrLst.html"))

// Rate limiter using a sliding window per IP
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	var recent []time.Time
	for _, t := range rl.visitors[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.visitors[ip] = recent
		return false
	}

	rl.visitors[ip] = append(recent, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for ip, times := range rl.visitors {
			var recent []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(rl.visitors, ip)
			} else {
				rl.visitors[ip] = recent
			}
		}
		rl.mu.Unlock()
	}
}

func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(r.RemoteAddr) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

type Cfg struct {
	ServerPort                string `yaml:"ServerPort"`
	ServerPortTLS             string `yaml:"ServerPortTLS"`
	CertPathCrt               string `yaml:"CertPathCrt"`
	CertPathKey               string `yaml:"CertPathKey"`
	EnableTLS                 bool   `yaml:"EnableTLS"`
	DisableNoTLS              bool   `yaml:"DisableNoTLS"`
	Key                       string `yaml:"Key"`
	DisableWOLWithoutusername bool   `yaml:"DisableWOLWithoutusername"`
	AllowOnlyWolWithKey       bool   `yaml:"AllowOnlyWolWithKey"`
}

var AppConfig Cfg

type PageListUser struct {
	IdUsrMac         []template.HTML
	ShowNotification bool
	NotificationType string
	NotificationMsg  string
}

// MagicPacket is a slice of 102 bytes containing the magic packet data.
type MagicPacket [102]byte

func main() {
	ReadConfig()

	limiter := newRateLimiter(30, time.Minute)

	//SQL
	if _, err := os.Stat("./sqlite-database.db"); errors.Is(err, os.ErrNotExist) {
		CreateDB()
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())

	if !AppConfig.DisableWOLWithoutusername {
		http.HandleFunc("/sendWOL", rateLimitMiddleware(limiter, sendWOL))
	}

	http.HandleFunc("/sendWOLuser", rateLimitMiddleware(limiter, func(w http.ResponseWriter, r *http.Request) {
		sendWOLuser(w, r, db)
	}))

	http.HandleFunc("/addUsrToMac", rateLimitMiddleware(limiter, func(w http.ResponseWriter, r *http.Request) {
		addUsrToMac(w, r, db)
	}))

	http.HandleFunc("/remUsrToMacWithId", rateLimitMiddleware(limiter, func(w http.ResponseWriter, r *http.Request) {
		remUsrToMacWithId(w, r, db)
	}))
	http.HandleFunc("/listUsrToMac", rateLimitMiddleware(limiter, func(w http.ResponseWriter, r *http.Request) {
		listUsrToMac(w, r, db)
	}))
	http.HandleFunc("/favicon.ico", faviconHandler)

	http.HandleFunc("/", http.HandlerFunc(IndexHandler))
	if !AppConfig.DisableNoTLS {
		http.ListenAndServe(":"+AppConfig.ServerPort, nil)
	}
	if AppConfig.EnableTLS {
		err := http.ListenAndServeTLS(":"+AppConfig.ServerPortTLS, AppConfig.CertPathCrt, AppConfig.CertPathKey, nil)
		fmt.Println(err)
	}
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/favicon.ico")
}

func sendWOLuser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	user := r.URL.Query().Get("user")
	port := r.URL.Query().Get("port")
	key := r.URL.Query().Get("key")

	// Check key first to avoid unnecessary processing
	if AppConfig.AllowOnlyWolWithKey {
		if key != AppConfig.Key {
			fmt.Println("Wrong Key! ", strings.Replace(key, "\n", "", -1))
			if key != "" {
				http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
			}
			return
		}
	}
	// Check user length before querying the database
	if len(user) > 20 {
		fmt.Println("user too long!")
		if key != "" {
			http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		}
		return
	}
	// Check port before sending the packet
	if port != "7" && port != "9" {
		port = "9"
	}
	mac := GetMacFromUsr(user, db)
	if mac == "0" {
		fmt.Println("User not found in the database: ", strings.Replace(user, "\n", "", -1))
		if key != "" {
			http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		}
		return
	}

	success := SendMagicPacket(mac, port, user)

	// Redirect back to the user list page with a status parameter
	if key != "" {
		status := "success"
		if !success {
			status = "failed"
		}
		http.Redirect(w, r, "/listUsrToMac?key="+key+"&wol="+status+"&user="+url.QueryEscape(user), http.StatusSeeOther)
	}
}

func SendMagicPacket(mac string, port string, user string) bool {
	packet, err := NewMagicPacket(mac)
	if err != nil {
		fmt.Println("Error creating magic packet:", err)
		return false
	}

	err1 := packet.Send("255.255.255.255")             // send to broadcast
	err2 := packet.SendPort("255.255.255.255", port) // specify receiving port

	if err1 != nil || err2 != nil {
		fmt.Println("Error sending magic packet:", err1, err2)
		return false
	}

	fmt.Println("Magic packet sent -> User:", strings.Replace(user, "\n", "", -1), " MAC: ", strings.Replace(mac, "\n", "", -1), " on port: ", strings.Replace(port, "\n", "", -1))
	return true
}

func addUsrToMac(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}
	// Check for missing parameters and max length before querying the database
	mac := r.URL.Query().Get("mac")
	user := r.URL.Query().Get("user")
	if user == "" || mac == "" {
		fmt.Println("Insert user and mac!")
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	} else if len(user) > 20 || len(mac) > 20 {
		fmt.Println("user or mac too long!")
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}
	// Parse MAC address before querying the database
	mac1, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Println("Invalid MAC adress: ", mac1, " ", strings.Replace(mac, "\n", "", -1))
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}

	// Use a prepared statement to check for existing user
	stmt, err := db.Prepare("select mac from UsrToMac WHERE NAME = ?")
	checkErr(err)
	defer stmt.Close()
	rows, err := stmt.Query(user)
	checkErr(err)
	defer rows.Close()

	if !rows.Next() {
		// No existing user, insert into the database
		stmt, err := db.Prepare("insert into UsrToMac(NAME, MAC) values(?, ?)")
		checkErr(err)
		defer stmt.Close()
		_, err = stmt.Exec(user, mac)
		checkErr(err)
	}

	// Create action success parameter for notification
	userAction := "added"
	if rows.Next() {
		userAction = "updated"
	}

	// Redirect back to the user list page with notification (URL-encode user for safety)
	http.Redirect(w, r, "/listUsrToMac?key="+key+"&action="+userAction+"&user="+url.QueryEscape(user), http.StatusSeeOther)
}

func remUsrToMacWithId(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" || len(id) > 20 || !isNumeric(id) {
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}

	// Get the username before deleting
	var userName string
	err := db.QueryRow("SELECT NAME FROM UsrToMac WHERE id = ?", id).Scan(&userName)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("No user found with id:", strings.Replace(id, "\n", "", -1))
			http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
			return
		}
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Delete the user
	res, err := db.Exec("DELETE from UsrToMac WHERE id = ?", id)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		log.Println("No user found with id:", strings.Replace(id, "\n", "", -1))
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}

	// Redirect back to the user list page with notification (URL-encode userName for safety)
	http.Redirect(w, r, "/listUsrToMac?key="+key+"&action=removed&user="+url.QueryEscape(userName), http.StatusSeeOther)
}

func GetMacFromUsr(user string, db *sql.DB) string {

	rows, err := db.Query("select mac from UsrToMac WHERE NAME = ?", user)
	checkErr(err)
	defer rows.Close()

	//Iterate through result set
	for rows.Next() {
		var mac string
		err := rows.Scan(&mac)
		checkErr(err)
		return mac
	}

	//check error, if any, that were encountered during iteration
	err = rows.Err()
	checkErr(err)
	return "0"
}
func listUsrToMac(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}

	stmt, err := db.Prepare("SELECT * FROM UsrToMac ORDER BY id")
	checkErr(err)
	defer stmt.Close()
	rows, err := stmt.Query()
	checkErr(err)
	defer rows.Close()

	//Iterate through result set
	var IdUsrMacList []template.HTML
	for rows.Next() {
		var id string
		var name string
		var mac string
		err := rows.Scan(&id, &name, &mac)
		checkErr(err)
		IdUsrMacList = append(IdUsrMacList, template.HTML(
				"<tr>"+
					"<td class=\"cell-id\" data-label=\"ID\">"+html.EscapeString(id)+"</td>"+
					"<td class=\"cell-name\" data-label=\"Name\">"+html.EscapeString(name)+"</td>"+
					"<td class=\"cell-mac\" data-label=\"MAC Address\">"+html.EscapeString(mac)+"</td>"+
					"<td class=\"cell-actions\" data-label=\"Remove\">"+
					"<a href=\"/remUsrToMacWithId?id="+url.QueryEscape(id)+"&key="+url.QueryEscape(key)+"\" class=\"btn btn-remove\">Remove</a>"+
					"</td>"+
					"<td class=\"cell-actions\" data-label=\"Wake\">"+
					"<a href=\"/sendWOLuser?user="+url.QueryEscape(name)+"&key="+url.QueryEscape(key)+"\" class=\"btn btn-wol\">Wake</a>"+
					"</td>"+
					"</tr>"))
	}

	// Initialize page data
	p := &PageListUser{
		IdUsrMac:         IdUsrMacList,
		ShowNotification: false,
	}

	// Check for notification parameters (escape user for safe rendering in JS context)
	wolStatus := r.URL.Query().Get("wol")
	action := r.URL.Query().Get("action")
	user := r.URL.Query().Get("user")

	if wolStatus == "success" && user != "" {
		p.ShowNotification = true
		p.NotificationType = "success"
		p.NotificationMsg = "Wake-on-LAN packet successfully sent to " + user
	} else if wolStatus == "failed" && user != "" {
		p.ShowNotification = true
		p.NotificationType = "error"
		p.NotificationMsg = "Failed to send Wake-on-LAN packet to " + user
	} else if action == "added" && user != "" {
		p.ShowNotification = true
		p.NotificationType = "success"
		p.NotificationMsg = "User '" + user + "' successfully added"
	} else if action == "updated" && user != "" {
		p.ShowNotification = true
		p.NotificationType = "success"
		p.NotificationMsg = "User '" + user + "' successfully updated"
	} else if action == "removed" && user != "" {
		p.ShowNotification = true
		p.NotificationType = "success"
		p.NotificationMsg = "User '" + user + "' successfully removed"
	}

	renderTemplate(w, "UsrLst", p)
}

func renderTemplate(w http.ResponseWriter, tmpl string, p *PageListUser) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func CreateDB() {
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()

	// create table
	_, err = db.Exec("create table UsrToMac (ID integer NOT NULL PRIMARY KEY AUTOINCREMENT, NAME string not null, MAC string not null); delete from UsrToMac;")
	checkErr(err)
}

func checkErr(err error, args ...string) {
	if err != nil {
		fmt.Println("Error")
		fmt.Println(err, " : ", args)
	}
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func sendWOL(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if AppConfig.AllowOnlyWolWithKey && key != AppConfig.Key {
		fmt.Println("Wrong Key! ", strings.Replace(key, "\n", "", -1))
		return
	}
	mac := r.URL.Query().Get("mac")
	port := r.URL.Query().Get("port")

	if (port != "7") && (port != "9") {
		port = "9"
	}
	//fmt.Println(mac)
	SendMagicPacket(mac, port, "-")
}

// NewMagicPacket allocates a new MagicPacket with the specified MAC.
func NewMagicPacket(macAddr string) (packet MagicPacket, err error) {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return packet, err
	}
	if len(mac) != 6 {
		return packet, errors.New("invalid EUI-48 MAC address")
	}
	// write magic bytes to packet
	copy(packet[0:], []byte{255, 255, 255, 255, 255, 255})
	copy(packet[6:], bytes.Repeat(mac, 16))
	return packet, nil
}

func sendUDPPacket(mp MagicPacket, addr string) (err error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(mp[:])
	return err
}

// Send writes the MagicPacket to the specified address on port 9.
func (mp MagicPacket) Send(addr string) error {
	return sendUDPPacket(mp, addr+":9")
}

// SendPort writes the MagicPacket to the specified address and port.
func (mp MagicPacket) SendPort(addr string, port string) error {
	return sendUDPPacket(mp, addr+":"+port)
}

func ReadConfig() {
	f, err := os.Open(configPath)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&AppConfig)

	if err != nil {
		fmt.Println(err)
	}
}

func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
