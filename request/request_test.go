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

func TestAWSGetClusters(t *testing.T) {
	accessKeyId := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")

	data, err := AWSGetClusters(accessKeyId, secretAccessKey, region)
	if err != nil {
		t.Errorf("Could not get clusters: %s", err.Error())
	}

	t.Logf(data)
}

func TestAWSGetToken(t *testing.T) {
	accessKeyId := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")
	clusterID := os.Getenv("AWS_CLUSTER_ID")

	data, err := AWSGetToken(accessKeyId, secretAccessKey, region, clusterID)
	if err != nil {
		t.Errorf("Could not get token: %s", err.Error())
	}

	t.Logf(data)
}

func TestAzureGetClusters(t *testing.T) {
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	resourceGroupName := os.Getenv("AZURE_RESOURCE_GROUP_NAME")

	data, err := AzureGetClusters(subscriptionID, clientID, clientSecret, tenantID, resourceGroupName, true)
	if err != nil {
		t.Errorf("Could not get clusters: %s", err.Error())
	}

	t.Logf(data)
}

func TestOIDCGetLink(t *testing.T) {
	discoveryURL := os.Getenv("OIDC_DISCOVERY_URL")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")

	data, err := OIDCGetLink(discoveryURL, clientID, clientSecret, redirectURL)
	if err != nil {
		t.Errorf("Could not get OIDC link: %s", err.Error())
	}

	t.Logf(data)
}

func TestOIDCGetRefreshToken(t *testing.T) {
	discoveryURL := os.Getenv("OIDC_DISCOVERY_URL")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")
	code := os.Getenv("OIDC_CODE")

	data, err := OIDCGetRefreshToken(discoveryURL, clientID, clientSecret, redirectURL, code)
	if err != nil {
		t.Errorf("Could not get OIDC refresh token: %s", err.Error())
	}

	t.Logf(data)
}

func TestOIDCGetAccessToken(t *testing.T) {
	discoveryURL := os.Getenv("OIDC_DISCOVERY_URL")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")
	refreshToken := os.Getenv("OIDC_REFRESH_TOKEN")

	data, err := OIDCGetAccessToken(discoveryURL, clientID, clientSecret, redirectURL, refreshToken)
	if err != nil {
		t.Errorf("Could not get OIDC access token: %s", err.Error())
	}

	t.Logf(data)
}
