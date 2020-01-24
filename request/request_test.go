// Usage:
//   export API_URL=
//   export CERTIFICATE_AUTHORITY_DATA=
//   export CLIENT_CERTIFICATE_DATA=
//   export CLIENT_KEY_DATA=
//   export API_TOKEN=
//   export API_USERNAME=
//   export API_PASSWORD=
//
//   make test
package request

import (
	"os"
	"testing"
)

func TestDoNamespaces(t *testing.T) {
	url := os.Getenv("API_URL")
	certificateAuthorityData := os.Getenv("CERTIFICATE_AUTHORITY_DATA")
	clientCertificateData := os.Getenv("CLIENT_CERTIFICATE_DATA")
	clientKeyData := os.Getenv("CLIENT_KEY_DATA")
	token := os.Getenv("API_TOKEN")
	username := os.Getenv("API_USERNAME")
	password := os.Getenv("API_PASSWORD")

	// Get namespaces
	data, err := Do("GET", url+"/api/v1/namespaces", "", certificateAuthorityData, clientCertificateData, clientKeyData, token, username, password)
	if err != nil {
		t.Errorf("Could not get namespaces: %s", err.Error())
	}

	t.Logf(data)
}

func TestDoNonexistingResource(t *testing.T) {
	url := os.Getenv("API_URL")
	certificateAuthorityData := os.Getenv("CERTIFICATE_AUTHORITY_DATA")
	clientCertificateData := os.Getenv("CLIENT_CERTIFICATE_DATA")
	clientKeyData := os.Getenv("CLIENT_KEY_DATA")
	token := os.Getenv("API_TOKEN")
	username := os.Getenv("API_USERNAME")
	password := os.Getenv("API_PASSWORD")

	// Try to get nonexisting resource
	_, err := Do("GET", url+"/api/v1/nonexisting-resource", "", certificateAuthorityData, clientCertificateData, clientKeyData, token, username, password)
	if err == nil {
		t.Errorf("Get resource instead of nonexisting resource error")
	}

	t.Logf(err.Error())
}
