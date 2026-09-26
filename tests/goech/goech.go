// ECH interop peer (Go crypto/tls, RFC 9849) for tests/interop.sh:
//
//	goech server <port> <list-out> <chain.pem> <key.pem> <public-chain.pem> <public-key.pem> [hrr]
//	    an ECH server (a fresh key, config id 7, public name other.example; its
//	    ECHConfigList written to list-out as hex) answering one request per
//	    connection with the status line "HTTP/1.1 200 sni=<name> ech=<bool>";
//	    hrr: P-256 only (a client sharing X25519 gets a HelloRetryRequest).
//	goech client <port> <list-hex-file> <root.pem> <name> [hrr]
//	    connects with that ECHConfigList and prints the answer and "ech=<bool>",
//	    or "rejected retry=<hex>" (exit 2) when the server refused ECH; hrr:
//	    shares X25519 only, prefers P-256.
//	goech genlist <out> <config-id>
//	    a list with a key nobody holds (a stale configuration).
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

func echConfig(id byte, pub []byte, publicName string) []byte {
	var c []byte
	c = append(c, id, 0x00, 0x20) // DHKEM(X25519, HKDF-SHA256)
	c = append(c, 0, byte(len(pub)))
	c = append(c, pub...)
	c = append(c, 0, 4, 0, 1, 0, 1)          // HKDF-SHA256, AES-128-GCM
	c = append(c, 32, byte(len(publicName))) // maximum_name_length, public_name
	c = append(c, publicName...)
	c = append(c, 0, 0) // no extensions
	return append([]byte{0xfe, 0x0d, byte(len(c) >> 8), byte(len(c))}, c...)
}

func list(cfg []byte) []byte {
	return append([]byte{byte(len(cfg) >> 8), byte(len(cfg))}, cfg...)
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "goech: "+f+"\n", a...)
	os.Exit(1)
}

func server(args []string) {
	if len(args) < 6 {
		die("server <port> <list-out> <chain> <key> <public-chain> <public-key> [hrr]")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		die("%v", err)
	}
	cfg := echConfig(7, key.PublicKey().Bytes(), "other.example")
	if err := os.WriteFile(args[1], []byte(hex.EncodeToString(list(cfg))), 0o644); err != nil {
		die("%v", err)
	}
	c1, err := tls.LoadX509KeyPair(args[2], args[3])
	if err != nil {
		die("%v", err)
	}
	c2, err := tls.LoadX509KeyPair(args[4], args[5])
	if err != nil {
		die("%v", err)
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c1, c2},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{
			{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true},
		},
	}
	if len(args) > 6 && args[6] == "hrr" {
		tc.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:"+args[0], tc)
	if err != nil {
		die("%v", err)
	}
	fmt.Println("goech server on", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			die("%v", err)
		}
		go func(conn net.Conn) {
			defer conn.Close()
			t := conn.(*tls.Conn)
			if err := t.Handshake(); err != nil {
				fmt.Println("handshake:", err)
				return
			}
			st := t.ConnectionState()
			r := bufio.NewReader(t)
			for {
				line, err := r.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			fmt.Fprintf(t, "HTTP/1.1 200 sni=%s ech=%v\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
				st.ServerName, st.ECHAccepted)
		}(conn)
	}
}

func client(args []string) {
	if len(args) < 4 {
		die("client <port> <list-hex-file> <root.pem> <name> [hrr]")
	}
	h, err := os.ReadFile(args[1])
	if err != nil {
		die("%v", err)
	}
	lst, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		die("%v", err)
	}
	pem, err := os.ReadFile(args[2])
	if err != nil {
		die("%v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tc := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     args[3],
		RootCAs:                        pool,
		EncryptedClientHelloConfigList: lst,
	}
	if len(args) > 4 && args[4] == "hrr" {
		tc.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+args[0], tc)
	if err != nil {
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			fmt.Printf("rejected retry=%s\n", hex.EncodeToString(rej.RetryConfigList))
			os.Exit(2)
		}
		die("%v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", args[3])
	body, _ := io.ReadAll(conn)
	fmt.Print(string(body))
	fmt.Printf("ech=%v\n", conn.ConnectionState().ECHAccepted)
}

func genlist(args []string) {
	if len(args) < 2 {
		die("genlist <out> <config-id>")
	}
	id, err := strconv.Atoi(args[1])
	if err != nil {
		die("%v", err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		die("%v", err)
	}
	cfg := echConfig(byte(id), key.PublicKey().Bytes(), "other.example")
	if err := os.WriteFile(args[0], []byte(hex.EncodeToString(list(cfg))), 0o644); err != nil {
		die("%v", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		die("server | client | genlist")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	case "genlist":
		genlist(os.Args[2:])
	default:
		die("unknown mode %s", os.Args[1])
	}
}
