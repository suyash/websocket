// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bytes"
	"net"
	"net/http"
	"net/url"

	"github.com/valyala/fasthttp"
)

// FastHTTPUpgrader specifies parameters for upgrading a FastHTTP connection to a
// WebSocket connection.
type FastHTTPUpgrader struct {
	// TODO: incorporate HandshakeTimeout
	// HandshakeTimeout                time.Duration
	ReadBufferSize, WriteBufferSize int
	Subprotocols                    [][]byte
	Error                           func(ctx *fasthttp.RequestCtx, status int, reason error)
	CheckOrigin                     func(ctx *fasthttp.Request) bool
	EnableCompression               bool

	// Handler is the function called when a new connection is initiated
	// It needs to block for the connection to stay open, the connection automatically
	// closes when this function exits
	Handler func(*Conn)
}

func (u *FastHTTPUpgrader) returnError(ctx *fasthttp.RequestCtx, status int, reason string) error {
	err := HandshakeError{reason}
	if u.Error != nil {
		u.Error(ctx, status, err)
	} else {
		ctx.Request.Header.Set("Sec-Websocket-Version", "13")
		ctx.Error(http.StatusText(status), status)
	}
	return err
}

func (u *FastHTTPUpgrader) selectSubprotocol(ctx *fasthttp.RequestCtx) string {
	if u.Subprotocols != nil {
		clientProtocols := FastHTTPSubprotocols(ctx)
		for _, serverProtocol := range u.Subprotocols {
			for _, clientProtocol := range clientProtocols {
				if string(clientProtocol) == string(serverProtocol) {
					return string(clientProtocol)
				}
			}
		}
	} else if ctx.Response.Header.Peek("Sec-Websocket-Protocol") != nil {
		return string(ctx.Response.Header.Peek("Sec-Websocket-Protocol"))
	}

	return ""
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// application negotiated subprotocol (Sec-Websocket-Protocol).
//
// If the upgrade fails, then Upgrade replies to the client with an HTTP error
// response.
func (u *FastHTTPUpgrader) Upgrade(ctx *fasthttp.RequestCtx) error {
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if !tokenListContainsValuefasthttp(&ctx.Request.Header, "Connection", "upgrade") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, badHandshake+"'upgrade' token not found in 'Connection' header")
	}

	if !tokenListContainsValuefasthttp(&ctx.Request.Header, "Upgrade", "websocket") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, badHandshake+"'websocket' token not found in 'Upgrade' header")
	}

	if string(ctx.Method()) != "GET" {
		return u.returnError(ctx, fasthttp.StatusMethodNotAllowed, badHandshake+"request method is not GET")
	}

	if !tokenListContainsValuefasthttp(&ctx.Request.Header, "Sec-Websocket-Version", "13") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	}

	if ctx.Response.Header.Peek("Sec-Websocket-Extensions") != nil {
		return u.returnError(ctx, fasthttp.StatusInternalServerError, "websocket: application specific 'Sec-Websocket-Extensions' headers are unsupported")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOriginfasthttp
	}
	if !checkOrigin(&ctx.Request) {
		return u.returnError(ctx, fasthttp.StatusForbidden, "websocket: request origin not allowed by FastHTTPUpgrader.CheckOrigin")
	}

	challengeKey := ctx.Request.Header.Peek("Sec-Websocket-Key")
	if challengeKey == nil {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: not a websocket handshake: `Sec-Websocket-Key' header is missing or blank")
	}

	// Negotiate PMCE
	var compress bool
	if u.EnableCompression {
		for _, ext := range parseExtensionsfasthttp(&ctx.Request.Header) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			compress = true
			break
		}
	}

	ctx.SetStatusCode(fasthttp.StatusSwitchingProtocols)
	ctx.Response.Header.Set("Upgrade", "websocket")
	ctx.Response.Header.Set("Connection", "Upgrade")
	ctx.Response.Header.Set("Sec-Websocket-Accept", computeAcceptKey(string(challengeKey)))

	subprotocol := u.selectSubprotocol(ctx)
	if subprotocol != "" {
		ctx.Response.Header.Set("Sec-Websocket-Protocol", subprotocol)
	}

	if compress {
		ctx.Response.Header.Set("Sec-Websocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}

	ctx.Hijack(func(netConn net.Conn) {
		c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize)
		c.subprotocol = subprotocol

		if compress {
			c.newCompressionWriter = compressNoContextTakeover
			c.newDecompressionReader = decompressNoContextTakeover
		}

		u.Handler(c)
	})

	return nil
}

// FastHTTPUpgrade FastHTTPUpgrade
func FastHTTPUpgrade(ctx *fasthttp.RequestCtx, readBufSize, writeBufSize int, handler func(*Conn)) error {
	u := FastHTTPUpgrader{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(ctx *fasthttp.RequestCtx, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(r *fasthttp.Request) bool {
		// allow all connections by default
		return true
	}
	u.Handler = handler
	return u.Upgrade(ctx)
}

// FastHTTPSubprotocols returns the subprotocols requested by the client in the
// Sec-Websocket-Protocol header.
func FastHTTPSubprotocols(ctx *fasthttp.RequestCtx) [][]byte {
	h := bytes.TrimSpace(ctx.Request.Header.Peek("Sec-Websocket-Protocol"))
	if h == nil {
		return nil
	}
	protocols := bytes.Split(h, []byte(","))
	for i := range protocols {
		protocols[i] = bytes.TrimSpace(protocols[i])
	}
	return protocols
}

// IsWebSocketUpgradeFastHTTP returns true if the client requested upgrade to the
// WebSocket protocol.
func IsWebSocketUpgradeFastHTTP(ctx *fasthttp.RequestCtx) bool {
	return tokenListContainsValuefasthttp(&ctx.Request.Header, "Connection", "upgrade") &&
		tokenListContainsValuefasthttp(&ctx.Request.Header, "Upgrade", "websocket")
}

// checkSameOrigin returns true if the origin is not set or is equal to the request host.
func checkSameOriginfasthttp(r *fasthttp.Request) bool {
	origin := r.Header.Peek("Origin")
	if origin == nil {
		return true
	}
	u, err := url.Parse(string(origin))
	if err != nil {
		return false
	}
	return equalASCIIFold(u.Host, string(r.Host()))
}
