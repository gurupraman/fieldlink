package soap

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

const testTemplate = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetItemStatus xmlns="http://legacy.example/">
      <ItemCode>{{.ItemCode}}</ItemCode>
    </GetItemStatus>
  </soap:Body>
</soap:Envelope>`

// startTestSOAPServer runs a real HTTP server that behaves like a minimal
// legacy SOAP endpoint: it checks the SOAPAction header, parses the
// envelope it received, and echoes the ItemCode back inside a canned
// response — real enough to prove the request FieldLink actually sent on
// the wire is well-formed and correctly parameterized, not just that the
// Go code compiles.
func startTestSOAPServer(t *testing.T, wantSOAPAction string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured.soapAction = r.Header.Get("SOAPAction")
		captured.contentType = r.Header.Get("Content-Type")
		captured.authUser, captured.authPass, captured.hasAuth = r.BasicAuth()
		captured.body = string(body)

		if wantSOAPAction != "" && r.Header.Get("SOAPAction") != wantSOAPAction {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Parse just enough to prove the request is well-formed XML and
		// to echo back what was actually received, not a fixed fixture.
		var env struct {
			XMLName xml.Name `xml:"Envelope"`
			Body    struct {
				GetItemStatus struct {
					ItemCode string `xml:"ItemCode"`
				} `xml:"GetItemStatus"`
			} `xml:"Body"`
		}
		if err := xml.Unmarshal(body, &env); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("parse error: " + err.Error()))
			return
		}

		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Write([]byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetItemStatusResponse xmlns="http://legacy.example/">
      <Status>OK</Status>
      <EchoedItemCode>` + xmlEscape(env.Body.GetItemStatus.ItemCode) + `</EchoedItemCode>
    </GetItemStatusResponse>
  </soap:Body>
</soap:Envelope>`))
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

type capturedRequest struct {
	soapAction  string
	contentType string
	authUser    string
	authPass    string
	hasAuth     bool
	body        string
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func grantedSOAPEngine(t *testing.T, endpoint, operation string) policy.Engine {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: soap.call
    constraints:
      endpoints: ["` + endpoint + `"]
      operations: ["` + operation + `"]
`
	g, canonical, err := grant.ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := dir + "/grant.yaml"
	if err := os.WriteFile(grantPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := dir + "/trusted.pub"
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	return policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
}

func TestCallSOAP_RealServer_Succeeds(t *testing.T) {
	srv, captured := startTestSOAPServer(t, "http://legacy.example/GetItemStatus")
	eng := grantedSOAPEngine(t, "legacy_erp", "GetItemStatus")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL:     srv.URL,
			Timeout: config.Duration(5 * time.Second),
			Operations: map[string]config.SOAPOperation{
				"GetItemStatus": {SOAPAction: "http://legacy.example/GetItemStatus", Template: testTemplate},
			},
		},
	}
	exec := NewExecutor(eng, endpoints)

	result, out, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "GetItemStatus",
		Params: map[string]string{"ItemCode": "WIDGET-42"},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}
	if result != nil && result.IsError {
		t.Fatalf("CallSOAP denied: %+v", result.Content)
	}
	if out.StatusCode != 200 {
		t.Fatalf("status = %d", out.StatusCode)
	}
	if !strings.Contains(out.Body, "<EchoedItemCode>WIDGET-42</EchoedItemCode>") {
		t.Fatalf("response body does not echo the sent ItemCode: %s", out.Body)
	}
	if captured.soapAction != "http://legacy.example/GetItemStatus" {
		t.Errorf("SOAPAction header = %q", captured.soapAction)
	}
	if !strings.Contains(captured.contentType, "text/xml") {
		t.Errorf("Content-Type = %q", captured.contentType)
	}
	if !strings.Contains(captured.body, "<ItemCode>WIDGET-42</ItemCode>") {
		t.Fatalf("request body sent on the wire does not contain the expected element: %s", captured.body)
	}
}

// TestCallSOAP_EscapesXMLInjectionAttempt is the security-critical test:
// a parameter value that looks like it's trying to close the ItemCode
// element and inject a sibling element must arrive on the wire as inert
// text content, not as parsed XML structure.
func TestCallSOAP_EscapesXMLInjectionAttempt(t *testing.T) {
	srv, captured := startTestSOAPServer(t, "")
	eng := grantedSOAPEngine(t, "legacy_erp", "GetItemStatus")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL:     srv.URL,
			Timeout: config.Duration(5 * time.Second),
			Operations: map[string]config.SOAPOperation{
				"GetItemStatus": {Template: testTemplate},
			},
		},
	}
	exec := NewExecutor(eng, endpoints)

	malicious := `</ItemCode><Injected>evil</Injected><ItemCode>`
	_, _, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "GetItemStatus",
		Params: map[string]string{"ItemCode": malicious},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}

	// The server must have received the request as well-formed XML with
	// no <Injected> element as a sibling — i.e. the malicious value must
	// appear as escaped text, never as parsed structure.
	if strings.Contains(captured.body, "<Injected>") {
		t.Fatalf("XML injection succeeded — raw <Injected> tag reached the wire unescaped:\n%s", captured.body)
	}
	if !strings.Contains(captured.body, "&lt;/ItemCode&gt;") && !strings.Contains(captured.body, "&lt;") {
		t.Fatalf("expected the malicious value to be XML-escaped in the request body:\n%s", captured.body)
	}

	// And decoding it back out must show it landed as the *content* of
	// ItemCode, not as sibling elements the server parsed separately.
	var env struct {
		Body struct {
			GetItemStatus struct {
				ItemCode string `xml:"ItemCode"`
			} `xml:"GetItemStatus"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal([]byte(captured.body), &env); err != nil {
		t.Fatalf("request body sent on the wire is not valid XML: %v\n%s", err, captured.body)
	}
	if env.Body.GetItemStatus.ItemCode != malicious {
		t.Fatalf("ItemCode content = %q, want the literal malicious string as inert text: %q",
			env.Body.GetItemStatus.ItemCode, malicious)
	}
}

func TestCallSOAP_DeniesUngrantedOperation(t *testing.T) {
	srv, _ := startTestSOAPServer(t, "")
	eng := grantedSOAPEngine(t, "legacy_erp", "SomeOtherOperation")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL: srv.URL,
			Operations: map[string]config.SOAPOperation{
				"GetItemStatus": {Template: testTemplate},
			},
		},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "GetItemStatus",
		Params: map[string]string{"ItemCode": "X"},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for an operation not present in the grant")
	}
}

func TestCallSOAP_DeniesUnconfiguredOperation(t *testing.T) {
	srv, _ := startTestSOAPServer(t, "")
	eng := grantedSOAPEngine(t, "legacy_erp", "NotConfigured")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL:        srv.URL,
			Operations: map[string]config.SOAPOperation{}, // nothing declared
		},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "NotConfigured",
		Params: map[string]string{"ItemCode": "X"},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for an operation not declared in config, even if named in the grant")
	}
}

func TestCallSOAP_MissingRequiredParamFailsClosed(t *testing.T) {
	srv, _ := startTestSOAPServer(t, "")
	eng := grantedSOAPEngine(t, "legacy_erp", "GetItemStatus")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL: srv.URL,
			Operations: map[string]config.SOAPOperation{
				"GetItemStatus": {Template: testTemplate},
			},
		},
	}
	exec := NewExecutor(eng, endpoints)

	// No ItemCode supplied at all — the template references {{.ItemCode}}.
	result, _, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "GetItemStatus",
		Params: map[string]string{},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true when a required template parameter is missing, not a silently empty element")
	}
}

func TestCallSOAP_SendsBasicAuthWhenConfigured(t *testing.T) {
	srv, captured := startTestSOAPServer(t, "")
	t.Setenv("TEST_SOAP_USER", "svc-account")
	t.Setenv("TEST_SOAP_PASS", "hunter2")

	eng := grantedSOAPEngine(t, "legacy_erp", "GetItemStatus")
	endpoints := map[string]config.SOAPEndpoint{
		"legacy_erp": {
			URL:         srv.URL,
			UsernameEnv: "TEST_SOAP_USER",
			PasswordEnv: "TEST_SOAP_PASS",
			Operations: map[string]config.SOAPOperation{
				"GetItemStatus": {Template: testTemplate},
			},
		},
	}
	exec := NewExecutor(eng, endpoints)

	_, _, err := exec.CallSOAP(context.Background(), nil, CallSOAPInput{
		Endpoint: "legacy_erp", Operation: "GetItemStatus",
		Params: map[string]string{"ItemCode": "X"},
	})
	if err != nil {
		t.Fatalf("CallSOAP: %v", err)
	}
	if !captured.hasAuth || captured.authUser != "svc-account" || captured.authPass != "hunter2" {
		t.Fatalf("expected HTTP Basic auth with configured credentials, got hasAuth=%v user=%q", captured.hasAuth, captured.authUser)
	}
}
