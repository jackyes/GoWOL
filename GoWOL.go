package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
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
	if !AppConfig.DisableWOLWithoutusername {
		sendWOL := http.HandlerFunc(sendWOL)
		http.Handle("/sendWOL", sendWOL)
	}
	sendWOLuser := http.HandlerFunc(sendWOLuser)
	http.Handle("/sendWOLuser", sendWOLuser)
	addUsrToMac := http.HandlerFunc(addUsrToMac)
	http.Handle("/addUsrToMac", addUsrToMac)
	remUsrToMac := http.HandlerFunc(remUsrToMac)
	http.Handle("/remUsrToMac", remUsrToMac)
	remUsrToMacWithId := http.HandlerFunc(remUsrToMacWithId)
	http.Handle("/remUsrToMacWithId", remUsrToMacWithId)
	listUsrToMac := http.HandlerFunc(listUsrToMac)
	http.Handle("/listUsrToMac", listUsrToMac)
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

func sendWOLuser(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	port := r.URL.Query().Get("port")
	if len(user) > 20 {
		fmt.Println("user too long!")
		return
	}
	if !(port == "7") && !(port == "9") {
		port = "9"
	}
	var mac string = GetMacFromUsr(user)
	if packet, err := NewMagicPacket(mac); err == nil {
		packet.Send("255.255.255.255")           // send to broadcast
		packet.SendPort("255.255.255.255", port) // specify receiving port
		fmt.Println("Magic packet sent -> User:", user, " MAC: ", mac, " on port: ", port)
	}
}
func addUsrToMac(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	mac := r.URL.Query().Get("mac")
	user := r.URL.Query().Get("user")
	if user == "" || mac == "" {
		fmt.Println("Insert user and mac!")
		return
	} else if len(user) > 20 || len(mac) > 20 {
		fmt.Println("user or mac too long!")
		return
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())
	tx, err := db.Begin()
	checkErr(err)
	stmt, err := tx.Prepare("insert into UsrToMac(NAME, MAC) values(?, ?)")
	checkErr(err)
	defer stmt.Close()
	_, err = stmt.Exec(user, mac)
	checkErr(err)
	tx.Commit()
}

func remUsrToMac(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	user := r.URL.Query().Get("user")
	if user == "" {
		return
	} else if len(user) > 20 {
		return //reject if user is too long
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())
	res, err := db.Exec("DELETE from UsrToMac WHERE NAME = ?", user)
	if err != nil {
		fmt.Println(err)
		fmt.Println(res)
	}
}

func remUsrToMacWithId(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		return
	} else if len(id) > 20 || !isNumeric(id) {
		return //reject if id is too long or not numeric
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())
	res, err := db.Exec("DELETE from UsrToMac WHERE id = ?", id)
	if err != nil {
		fmt.Println(err)
		fmt.Println(res)
	}
}

func GetMacFromUsr(user string) string {
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())
	rows, err := db.Query("select mac from UsrToMac WHERE NAME = ?", user)
	checkErr(err)
	defer rows.Close()

	//5.1 Iterate through result set
	for rows.Next() {
		var mac string
		err := rows.Scan(&mac)
		checkErr(err)
		return mac
	}

	//5.2 check error, if any, that were encountered during iteration
	err = rows.Err()
	checkErr(err)
	return "0"
}
func listUsrToMac(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key != AppConfig.Key {
		fmt.Println("Wrong Key!")
		return
	}
	db, err := sql.Open("sqlite3", "sqlite-database.db")
	checkErr(err)
	defer db.Close()
	checkErr(db.Ping())
	rows, err := db.Query("SELECT * FROM UsrToMac ORDER BY id")
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
		IdUsrMacList = append(IdUsrMacList, "<tr><td>"+id+"</td><td>"+name+"</td><td>"+mac+"</td><td> <a href=\"/remUsrToMacWithId?id="+id+"&key="+key+"\"> Remove User</a> </td><td><a href=\"/remUsrToMac?user="+name+"&key="+key+"\"> Remove all with same name</a></td><td> <a href=\"/sendWOLuser?user="+name+"\"> Send WOL packet</a> </td></tr>")
	}

	p := &PageListUser{
		IdUsrMac: IdUsrMacList,
	}

	renderTemplate(w, "UsrLst", p)

	//5.2 check error, if any, that were encountered during iteration
	err = rows.Err()
	checkErr(err)
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
	checkErr(db.Ping())

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
	mac := r.URL.Query().Get("mac")
	port := r.URL.Query().Get("port")

	if !(port == "7") && !(port == "9") {
		port = "9"
	}
	//fmt.Println(mac)
	if packet, err := NewMagicPacket(mac); err == nil {
		packet.Send("255.255.255.255")           // send to broadcast
		packet.SendPort("255.255.255.255", port) // specify receiving port
		fmt.Println("Magic packet sent -> MAC: ", mac, " on port: ", port)
	}
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
	offset := 6

	for i := 0; i < 16; i++ {
		copy(packet[offset:], mac)
		offset += 6
	}

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
