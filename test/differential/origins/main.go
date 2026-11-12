// Command origins reads request bodies (one JSON object {"id", "body"} per line) and
// prints whether each origin model would accept them on add-chain and add-pre-chain:
//
//	id <TAB> model <TAB> add-chain verdict <TAB> add-pre-chain verdict
//
// where a verdict is "accept" or "reject". The models apply each origin's real JSON
// and X.509 parsers, and its checks of the chain's names and precertificate status,
// but don't verify signatures or apply a log's acceptance policy, as the snippet
// doesn't either, and they reject a body larger than the origin's default limit. A
// model's "accept" therefore means that the origin would accept the request if its
// signatures were valid and its policy allowed it.
package main

import (
	"bufio"
	"bytes"
	stdx509 "crypto/x509"
	stdasn1 "encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var poison = stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// All three origins decode the body with Go's encoding/json into this, and reject an
// empty chain.
type addChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// tesseract models TesseraCT: Go's crypto/x509, issuer names matching the next
// certificate's subject byte for byte, and its IsPrecertificate().
func tesseract(chain [][]byte, preChain bool) bool {
	var certs []*stdx509.Certificate
	for _, der := range chain {
		c, err := stdx509.ParseCertificate(der)
		if err != nil {
			return false
		}
		certs = append(certs, c)
	}
	for i := 0; i+1 < len(certs); i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return false
		}
	}
	isPrecert := false
	for _, e := range certs[0].Extensions {
		if e.Id.Equal(poison) {
			if !e.Critical || !bytes.Equal(e.Value, stdasn1.NullBytes) {
				return false
			}
			isPrecert = true
			break
		}
	}
	return isPrecert == preChain
}

// ctgo models Sunlight (rejectPreIssuers) and Trillian: ctfe.ValidateChain()'s limit on
// the chain's length (if any), certificate-transparency-go's x509 package and
// ctfe.IsPrecertificate(), with issuer names matching the next certificate's subject
// byte for byte (as its chain verification requires).
func ctgo(chain [][]byte, preChain, rejectPreIssuers bool) bool {
	if chainTooLong(len(chain)) {
		return false
	}
	var certs []*x509.Certificate
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if x509.IsFatal(err) {
			return false
		}
		certs = append(certs, c)
	}
	for i := 0; i+1 < len(certs); i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return false
		}
	}
	isPrecert, err := ctfe.IsPrecertificate(certs[0])
	if err != nil {
		return false
	}
	if rejectPreIssuers && isPrecert && len(certs) > 1 && ct.IsPreIssuer(certs[1]) {
		return false
	}
	return isPrecert == preChain
}

// chainTooLong returns whether ctfe.ValidateChain() rejects a chain of n certificates for
// its length, as it does for more than 100 since certificate-transparency-go bc63c417.
// It checks that before parsing them, so a chain of empty certificates either fails
// that check, or fails to parse.
func chainTooLong(n int) bool {
	if n == 0 {
		return false // ValidateChain() would panic.
	}
	opts := ctfe.NewCertValidationOpts(x509util.NewPEMCertPool(), time.Time{}, false, false, nil, nil, false, nil)
	_, err := ctfe.ValidateChain(make([][]byte, n), opts)
	return err != nil && strings.Contains(err.Error(), "exceeds maximum allowed length")
}

type model struct {
	accepts func(chain [][]byte, preChain bool) bool
	// The default maximum request body size, beyond which the origin's
	// http.MaxBytesHandler makes it reject the request.
	maxBodyBytes int
}

var models = map[string]model{
	// --max_cert_chain_bytes (cmd/tesseract/*/main.go)
	"tesseract": {tesseract, 512 << 10},
	// Fixed (internal/ctlog/http.go)
	"sunlight": {func(chain [][]byte, preChain bool) bool { return ctgo(chain, preChain, true) }, 128 * 1024},
	// --max_cert_chain_size (trillian/ctfe/ct_server/main.go); its handlers also limit
	// POST bodies to 512 KiB, since certificate-transparency-go bc63c417.
	"trillian": {func(chain [][]byte, preChain bool) bool { return ctgo(chain, preChain, false) }, 512000},
}

func main() {
	names := flag.String("models", "tesseract,sunlight,trillian", "comma-separated origin models to apply")
	flag.Parse()
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<22), 1<<22)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		var item struct{ ID, Body string }
		if err := json.Unmarshal(in.Bytes(), &item); err != nil {
			log.Fatal(err)
		}
		var req addChainRequest
		parsed := json.Unmarshal([]byte(item.Body), &req) == nil && len(req.Chain) > 0
		verdict := func(accept bool) string {
			if parsed && accept {
				return "accept"
			}
			return "reject"
		}
		for _, name := range strings.Split(*names, ",") {
			model, ok := models[name]
			if !ok {
				log.Fatalf("unknown model %q", name)
			}
			addChain, addPreChain := false, false
			if parsed && len(item.Body) <= model.maxBodyBytes {
				addChain, addPreChain = model.accepts(req.Chain, false), model.accepts(req.Chain, true)
			}
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", item.ID, name, verdict(addChain), verdict(addPreChain))
		}
	}
	if err := in.Err(); err != nil {
		log.Fatal(err)
	}
}
