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
	IdUsrMac []string
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

// faviconHandler serves the favicon file.
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/favicon.ico")
}

// sendWOLuser sends a Wake-on-LAN packet to the user specified in the request.
func sendWOLuser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	user := r.URL.Query().Get("user")
	port := r.URL.Query().Get("port")
	key := r.URL.Query().Get("key")

	// Check key first to avoid unnecessary processing
	if AppConfig.AllowOnlyWolWithKey {
		if key != AppConfig.Key {
			fmt.Println("Wrong Key! ", strings.Replace(key, "\n", "", -1))
			return
		}
	}
	// Check user length before querying the database
	if len(user) > 20 {
		fmt.Println("user too long!")
		return
	}
	// Check port before sending the packet
	if port != "7" && port != "9" {
		port = "9"
	}
	mac := GetMacFromUsr(user, db)
	if mac == "0" {
		fmt.Println("User not found in the database: ", strings.Replace(user, "\n", "", -1))
		return
	}

	SendMagicPacket(mac, port, user)
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// SendMagicPacket sends a Wake-on-LAN packet to the specified MAC address.
func SendMagicPacket(mac string, port string, user string) {
	if packet, err := NewMagicPacket(mac); err == nil {
		packet.Send("255.255.255.255")           // send to broadcast
		packet.SendPort("255.255.255.255", port) // specify receiving port
		fmt.Println("Magic packet sent -> User:", strings.Replace(user, "\n", "", -1), " MAC: ", strings.Replace(mac, "\n", "", -1), " on port: ", strings.Replace(port, "\n", "", -1))
	}
}

// addUsrToMac adds a user to the MAC address specified in the request.
func addUsrToMac(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	// Check for missing parameters and max length before querying the database
	mac := r.URL.Query().Get("mac")
	user := r.URL.Query().Get("user")
	if user == "" || mac == "" {
		fmt.Println("Insert user and mac!")
		return
	} else if len(user) > 20 || len(mac) > 20 {
		fmt.Println("user or mac too long!")
		return
	}
	// Parse MAC address before querying the database
	mac1, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Println("Invalid MAC adress: ", mac1, " ", strings.Replace(mac, "\n", "", -1))
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
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// remUsrToMacWithId removes a user from the MAC address specified in the request.
func remUsrToMacWithId(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" || len(id) > 20 || !isNumeric(id) {
		return
	}

	res, err := db.Exec("DELETE from UsrToMac WHERE id = ?", id)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if rowsAffected == 0 {
		log.Println("No user found with id:", strings.Replace(id, "\n", "", -1))
	}
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// GetMacFromUsr retrieves the MAC address associated with the specified user.
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

// listUsrToMac lists all users and their associated MAC addresses.
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
	//5.1 Iterate through result set
	var IdUsrMacList []string
	for rows.Next() {
		var id string
		var name string
		var mac string
		err := rows.Scan(&id, &name, &mac)
		checkErr(err)
		IdUsrMacList = append(IdUsrMacList, "<tr><td>"+id+"</td><td>"+name+"</td><td>"+mac+"</td><td> <a href=\"/remUsrToMacWithId?id="+id+"&key="+key+"\"> Remove User</a> </td><td> <a href=\"/sendWOLuser?user="+name+"\"> Send WOL packet</a> </td></tr>")
	}

	p := &PageListUser{
		IdUsrMac: IdUsrMacList,
	}

	renderTemplate(w, "UsrLst", p)
}

// renderTemplate renders the specified template.
func renderTemplate(w http.ResponseWriter, tmpl string, p *PageListUser) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CreateDB creates the database.
func CreateDB() {
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()

	// create table
	_, err = db.Exec("create table UsrToMac (ID integer NOT NULL PRIMARY KEY AUTOINCREMENT, NAME string not null, MAC string not null); delete from UsrToMac;")
	checkErr(err)
}

// checkErr checks for errors and prints them if they exist.
func checkErr(err error, args ...string) {
	if err != nil {
		fmt.Println("Error")
		fmt.Println(err, " : ", args)
	}
}

// IndexHandler handles requests to the root URL.
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// sendWOL sends a Wake-on-LAN packet.
func sendWOL(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if AppConfig.AllowOnlyWolWithKey && key != AppConfig.Key {
		fmt.Println("Wrong Key! ", strings.Replace(key, "\n", "", -1))
		return
	}
	mac := r.URL.Query().Get("mac")
	port := r.URL.Query().Get("port")

	if !(port == "7") && !(port == "9") {
		port = "9"
	}
	//fmt.Println(mac)
	SendMagicPacket(mac, port, "-")
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
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

// sendUDPPacket sends a UDP packet.
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

// ReadConfig reads the configuration file.
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

// isNumeric checks if a string is numeric.
func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
