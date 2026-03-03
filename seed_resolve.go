package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blocknet/p2p"
)

const (
	MainnetP2PPort    = 28080
	MainnetPeerIDPort = 28081
	TestnetP2PPort    = 38080
	TestnetPeerIDPort = 38081
)

var DefaultSeedIPs = []string{
	"46.62.203.242",
	"46.62.243.192",
	"46.62.252.254",
	"46.62.202.165",
	"46.62.249.240",
	"46.62.201.220",
}

// ResolveSeedNodes fetches peer IDs from seed nodes' HTTP endpoints
// and builds full multiaddrs. Fetches run in parallel with a 3s timeout.
func ResolveSeedNodes(ips []string, p2pPort, peerIDPort int) []string {
	type result struct {
		addr string
	}

	ch := make(chan result, len(ips))
	client := &http.Client{Timeout: 3 * time.Second}

	for _, ip := range ips {
		go func(ip string) {
			url := fmt.Sprintf("http://%s:%d/", ip, peerIDPort)
			resp, err := client.Get(url)
			if err != nil {
				ch <- result{}
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				ch <- result{}
				return
			}
			peerID := strings.TrimSpace(string(body))
			if peerID == "" {
				ch <- result{}
				return
			}
			ch <- result{fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", ip, p2pPort, peerID)}
		}(ip)
	}

	var seeds []string
	for range ips {
		if r := <-ch; r.addr != "" {
			seeds = append(seeds, r.addr)
		}
	}
	return seeds
}

func startPeerIDServer(node *p2p.Node, port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, node.PeerID().String())
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Peer ID endpoint failed on port %d: %v", port, err)
		}
	}()

	return server
}

func peerIDPortFromMultiaddr(listenAddr string) int {
	parts := strings.Split(listenAddr, "/")
	for i, p := range parts {
		if p == "tcp" && i+1 < len(parts) {
			if port, err := strconv.Atoi(parts[i+1]); err == nil {
				return port + 1
			}
		}
	}
	return MainnetPeerIDPort
}
