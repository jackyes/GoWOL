package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"

	_ "github.com/mattn/go-sqlite3"

	"gopkg.in/yaml.v3"
)

const configPath = "./config.yaml"

var templates = template.Must(template.ParseFiles("template/UsrLst.html"))

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
	IdUsrMac         []string
	ShowNotification bool
	NotificationType string
	NotificationMsg  string
}

// MagicPacket is a slice of 102 bytes containing the magic packet data.
type MagicPacket [102]byte

func main() {
	ReadConfig()
	//SQL
	if _, err := os.Stat("./sqlite-database.db"); errors.Is(err, os.ErrNotExist) {
		CreateDB()
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())

	if !AppConfig.DisableWOLWithoutusername {
		sendWOL := http.HandlerFunc(sendWOL)
		http.Handle("/sendWOL", sendWOL)
	}

	http.HandleFunc("/sendWOLuser", func(w http.ResponseWriter, r *http.Request) {
		sendWOLuser(w, r, db)
	})

	http.HandleFunc("/addUsrToMac", func(w http.ResponseWriter, r *http.Request) {
		addUsrToMac(w, r, db)
	})

	http.HandleFunc("/remUsrToMacWithId", func(w http.ResponseWriter, r *http.Request) {
		remUsrToMacWithId(w, r, db)
	})
	http.HandleFunc("/listUsrToMac", func(w http.ResponseWriter, r *http.Request) {
		listUsrToMac(w, r, db)
	})
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
		http.Redirect(w, r, "/listUsrToMac?key="+key+"&wol="+status+"&user="+user, http.StatusSeeOther)
	}
}

func SendMagicPacket(mac string, port string, user string) bool {
	packet, err := NewMagicPacket(mac)
	if err != nil {
		fmt.Println("Error creating magic packet:", err)
		return false
	}

	err1 := packet.Send("255.255.255.255")           // send to broadcast
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

	// Redirect back to the user list page with notification
	http.Redirect(w, r, "/listUsrToMac?key="+key+"&action="+userAction+"&user="+user, http.StatusSeeOther)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete the user
	res, err := db.Exec("DELETE from UsrToMac WHERE id = ?", id)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		log.Println("No user found with id:", strings.Replace(id, "\n", "", -1))
		http.Redirect(w, r, "/listUsrToMac?key="+key, http.StatusSeeOther)
		return
	}

	// Redirect back to the user list page with notification
	http.Redirect(w, r, "/listUsrToMac?key="+key+"&action=removed&user="+userName, http.StatusSeeOther)
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
	var IdUsrMacList []string
	for rows.Next() {
		var id string
		var name string
		var mac string
		err := rows.Scan(&id, &name, &mac)
		checkErr(err)
		IdUsrMacList = append(IdUsrMacList,
			"<tr>"+
				"<td class=\"cell-id\">"+id+"</td>"+
				"<td class=\"cell-name\">"+name+"</td>"+
				"<td class=\"cell-mac\">"+mac+"</td>"+
				"<td class=\"cell-actions\">"+
				"<a href=\"/remUsrToMacWithId?id="+id+"&key="+key+"\" class=\"btn btn-remove\">🗑️ Remove</a>"+
				"</td>"+
				"<td class=\"cell-actions\">"+
				"<a href=\"/sendWOLuser?user="+name+"&key="+key+"\" class=\"btn btn-wol\">🌐 Wake</a>"+
				"</td>"+
				"</tr>")
	}

	// Initialize page data
	p := &PageListUser{
		IdUsrMac:         IdUsrMacList,
		ShowNotification: false,
	}

	// Check for notification parameters
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
