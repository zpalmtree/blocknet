package p2p

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestBanGater_BlocksBannedPeerOnDialAndSecured(t *testing.T) {
	bannedPeer := peer.ID("12D3KooWBannedPeer123456789")
	gater := NewBanGater(func(pid peer.ID) bool {
		return pid == bannedPeer
	})

	if gater.InterceptPeerDial(bannedPeer) {
		t.Fatal("expected banned peer dial to be blocked")
	}

	addr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/28080")
	if err != nil {
		t.Fatalf("failed to build multiaddr: %v", err)
	}
	if gater.InterceptAddrDial(bannedPeer, addr) {
		t.Fatal("expected banned peer addr dial to be blocked")
	}

	if gater.InterceptSecured(network.DirInbound, bannedPeer, nil) {
		t.Fatal("expected banned peer secured connection to be blocked")
	}
}

func TestBanGater_AllowsNonBannedPeer(t *testing.T) {
	bannedPeer := peer.ID("12D3KooWBannedPeer123456789")
	goodPeer := peer.ID("12D3KooWGoodPeer1234567890")
	gater := NewBanGater(func(pid peer.ID) bool {
		return pid == bannedPeer
	})

	if !gater.InterceptPeerDial(goodPeer) {
		t.Fatal("expected non-banned peer dial to be allowed")
	}

	addr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/28080")
	if err != nil {
		t.Fatalf("failed to build multiaddr: %v", err)
	}
	if !gater.InterceptAddrDial(goodPeer, addr) {
		t.Fatal("expected non-banned peer addr dial to be allowed")
	}

	if !gater.InterceptSecured(network.DirOutbound, goodPeer, nil) {
		t.Fatal("expected non-banned peer secured connection to be allowed")
	}

	// InterceptAccept is intentionally permissive until peer identity is known.
	if !gater.InterceptAccept(nil) {
		t.Fatal("expected pre-handshake accept to be allowed")
	}
}
