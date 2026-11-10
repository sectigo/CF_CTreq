// Command origins reads request bodies (one JSON object {"id", "body"} per line) and
// prints whether each origin model would accept them on add-chain and add-pre-chain:
//
//	id <TAB> model <TAB> add-chain verdict <TAB> add-pre-chain verdict
//
// where a verdict is "accept" or "reject". The models apply each origin's real JSON
// and X.509 parsers, and its checks of the chain's names and precertificate status,
// but don't verify signatures or apply a log's acceptance policy, as the snippet
// doesn't either. A model's "accept" therefore means that the origin would accept the
// request if its signatures were valid and its policy allowed it.
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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
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

// ctgo models Sunlight (rejectPreIssuers) and Trillian: certificate-transparency-go's
// x509 package and ctfe.IsPrecertificate(), with issuer names matching the next
// certificate's subject byte for byte (as its chain verification requires).
func ctgo(chain [][]byte, preChain, rejectPreIssuers bool) bool {
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

var models = map[string]func(chain [][]byte, preChain bool) bool{
	"tesseract": tesseract,
	"sunlight":  func(chain [][]byte, preChain bool) bool { return ctgo(chain, preChain, true) },
	"trillian":  func(chain [][]byte, preChain bool) bool { return ctgo(chain, preChain, false) },
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
			if parsed {
				addChain, addPreChain = model(req.Chain, false), model(req.Chain, true)
			}
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", item.ID, name, verdict(addChain), verdict(addPreChain))
		}
	}
	if err := in.Err(); err != nil {
		log.Fatal(err)
	}
}
