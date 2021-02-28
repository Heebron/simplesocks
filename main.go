package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	addrPort               = regexp.MustCompile("([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}):([0-9]+)")
	unsupportedAddressType = []byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	hostUnreachable        = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	generalSocksError      = []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	notAllowedByRuleset    = []byte{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	commandNotSupported    = []byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	config struct {
		Blacklist []struct {
			Match []string `yaml:"match"`
			Block []string `yaml:"block"`
		} `yaml:Blacklist`
		SOCKSServer struct {
			Bind string `yaml:"bind"`
			Port int    `yaml:"port"`
		} `yaml:"SOCKS Server"`
		WADServer struct {
			Bind string `yaml:"bind"`
			Port int    `yaml:"port"`
		} `yaml:"WAD Server"`
	}
)

const (
	NoAuth = 0x00
)

func loadConfig(file *string) error {
	if data, err := ioutil.ReadFile(*file); err != nil {
		return err
	} else if err = yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	return nil
}
func main() {
	configFile := flag.String("config", "./config.yaml", "Configuration file.")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatal(err)
	}

	// https://www.davidpashley.com/articles/automatic-proxy-configuration-with-wpad/
	// http://192.168.10.12:3129/wpad.pac
	http.HandleFunc("/wpad.pac", func(w http.ResponseWriter, r *http.Request) {
		log.Println("INFO: wpad.pac served to web client from", r.RemoteAddr)
		w.Header().Add("Content-Type", "application/javascript")
		w.Write([]byte(
			`function FindProxyForURL(url,host)
	{
	 return "SOCKS5 192.168.10.12:3128";
	}
	`))
	})

	go http.ListenAndServe(fmt.Sprintf("%s:%d", config.WADServer.Bind, config.WADServer.Port), nil)

	log.Println("supersocks WPAD listening on ", fmt.Sprintf("%s:%d", config.WADServer.Bind, config.WADServer.Port))

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.SOCKSServer.Bind, config.SOCKSServer.Port))

	if err != nil {
		log.Fatal(err)
	}

	log.Println("supersocks SOCKS listening on ", ln.Addr())
	for {
		var conn net.Conn
		conn, err = ln.Accept()

		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	var err error
	var buffer = make([]byte, 8192)
	var clientName string
	var destConn net.Conn
	var destPort, localPort uint16
	var localAddr net.IP
	var destHost string

	// Make sure to clean up.
	defer conn.Close()

	// Get a client name.
	clientName = findClientName(conn, clientName)

	//log.Printf("INFO: [%d] %s Client.", numConnections, conn.RemoteAddr())

	// | VER | NMETHODS |
	// |  1  |    1     |

	// Must be version 0x05.
	if err = readN(conn, buffer, 2); err != nil {
		logError(clientName, err)
		return
	}

	if buffer[0] != 0x05 {
		log.Printf("TERM: %s Invalid version 0x%x. Expected 0x05.", clientName, buffer[0])
		return
	}

	// Get authorization methods
	nMethods := int(buffer[1])
	if err = readN(conn, buffer, nMethods); err != nil {
		logError(clientName, err)
		return
	}
	//log.Printf("INFO: %s Offered auth methods %v.", clientName, buffer[:nMethods])

	if bytes.IndexByte(buffer[:nMethods], NoAuth) == -1 {
		log.Printf("TERM: %s No acceptible authorization schemes offered.", clientName)
		conn.Write([]byte{0x05, 0xff})
		return
	}

	//log.Printf("INFO: %s Using no authorization.", clientName)
	if _, err = conn.Write([]byte{0x05, NoAuth}); err != nil {
		logError(clientName, err)
		return
	}

	// We are now connected. Process command.

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	if err = readN(conn, buffer, 4); err != nil {
		logError(clientName, err)
		return
	} else if buffer[0] != 0x05 {
		log.Printf("TERM: %s Invalid version 0x%x. Expected 0x05.", clientName, buffer[0])
		return
	} else if buffer[2] != 0x00 {
		log.Printf("TERM: %s RSV field is not 0. It is 0x%x.", clientName, buffer[2])
		return
	}

	switch buffer[1] {
	case 0x01: // CONNECT
		switch buffer[3] {
		case 0x01: // IPv4 (4 octets)
			if err = readN(conn, buffer, 4); err != nil {
				logError(clientName, err)
				return
			}
			destHost = net.IPv4(buffer[0], buffer[1], buffer[2], buffer[3]).String()
		case 0x03: // FQDN first octet is number of octets
			if err = readN(conn, buffer, 1); err != nil {
				logError(clientName, err)
				return
			}
			l := int(buffer[0])
			if err = readN(conn, buffer, l); err != nil {
				logError(clientName, err)
				return
			}
			destHost = string(buffer[:l])
		case 0x04: // IPv6 (16 octets)
			if err = readN(conn, buffer, 16); err != nil {
				logError(clientName, err)
				return
			}
			destAddr := net.IP{}
			copy(buffer[:16], destAddr)
			destHost = "[" + destAddr.String() + "]"
		default:
			conn.Write(unsupportedAddressType)
			log.Printf("INFO: %s Unsupported address type 0x%x. Disonnected.", clientName, buffer[3])
			return // Must terminate on non 0x00 response.
		}

		// Get the port.
		if err = readN(conn, buffer, 2); err != nil {
			logError(clientName, err)
			return
		}
		destPort = binary.BigEndian.Uint16(buffer[:2])

		// Is it allowed?
		if strings.Contains(destHost, "playboy.com") {
			conn.Write(notAllowedByRuleset)
			log.Printf("INFO: %s Connection to %s from %s not allowed. Disonnected.", clientName, destHost, conn.RemoteAddr())
			return
		}

		if destConn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", destHost, destPort), time.Second*30); err != nil {
			logError(clientName, err)
			// Return a host unreachable.
			conn.Write(hostUnreachable)
			log.Printf("INFO: %s Disonnected from %s. Host unreachable", clientName, destHost)
			return // Must terminate on non 0x00 response.
		}

		// clean up
		defer destConn.Close()

		// Return succeeded.
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+

		localAddr, localPort, err = toIpAndPort(destConn.LocalAddr())
		if err != nil {
			logError(clientName, err)
			return
		}

		// Send success ACK.
		_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, localAddr[0], localAddr[1], localAddr[2], localAddr[3], byte(localPort >> 8), byte(localPort)})
		if err != nil {
			logError(clientName, err)
			return
		}

		log.Printf("INFO: %s -> %s:%d", clientName, destHost, destPort)

		// Tunnel established

		block := make(chan bool, 2)
		go transfer(conn, destConn, block)
		go transfer(destConn, conn, block)
		<-block // Wait for either to finish
		log.Printf("INFO: %s <- %s:%d", clientName, destHost, destPort)
		return

	//case 0x02: // BIND
	//case 0x03: // UDP
	default:
		log.Printf("TERM: %s Unsupported command %d received.", clientName, buffer[1])
		conn.Write(commandNotSupported)
		return
	}
}

func findClientName(conn net.Conn, clientName string) string {
	bd := addrPort.FindStringSubmatch(conn.RemoteAddr().String())
	if names, err := net.LookupAddr(bd[1]); err != nil {
		clientName = conn.RemoteAddr().String()
	} else {
		if len(names) == 3 {
			clientName = names[1] + ":" + names[2]
		} else {
			clientName = names[0]
		}
	}
	return clientName
}

func logError(conn string, err error) {
	log.Printf("TERM: %s Received error: %s", conn, err)
}

func toIpAndPort(addr net.Addr) (net.IP, uint16, error) {
	idx := strings.LastIndex(addr.String(), ":")
	if idx == -1 {
		return nil, 0, errors.New("syntax error. missing ':'")
	}

	p, err := strconv.Atoi(addr.String()[idx+1:])

	if err != nil {
		return nil, 0, err
	}

	return net.ParseIP(addr.String()[:idx]), uint16(p), nil
}

func transfer(destination io.WriteCloser, source io.ReadCloser, n chan<- bool) {
	io.Copy(destination, source)
	n <- true
}

func readN(conn net.Conn, buffer []byte, expected int) error {
	if n, err := conn.Read(buffer[:expected]); err != nil {
		return err
	} else if n != expected {
		if expected == 1 {
			return errors.New(fmt.Sprintf("Expected 1 byte, got %d.", n))
		} else {
			return errors.New(fmt.Sprintf("Expected %d bytes, got %d.", expected, n))
		}
	} else {
		return nil
	}
}
