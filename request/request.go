package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/containerservice/mgmt/2020-01-01/containerservice"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

type APIError struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Reason     string `json:"reason"`
	Code       int    `json:"code"`
}

// Do runs the given HTTP request.
func Do(method, url, body, certificateAuthorityData, clientCertificateData, clientKeyData, token, username, password string, insecureSkipTLSVerify bool, timeout int64) (string, error) {
	var tlsConfig *tls.Config
	var err error

	tlsConfig, err = httpClientForRootCAs(certificateAuthorityData, clientCertificateData, clientKeyData, insecureSkipTLSVerify)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
		},
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")

	if method == "PATCH" {
		req.Header.Set("Content-Type", "application/json-patch+json")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		var apiError APIError
		err := json.NewDecoder(resp.Body).Decode(&apiError)
		if err != nil {
			return "", fmt.Errorf(resp.Status)
		}

		return "", fmt.Errorf(apiError.Message)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// httpClientForRootCAs return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(certificateAuthorityData, clientCertificateData, clientKeyData string, insecureSkipTLSVerify bool) (*tls.Config, error) {
	tlsConfig := tls.Config{}

	if certificateAuthorityData != "" {
		tlsConfig = tls.Config{RootCAs: x509.NewCertPool()}
		rootCA := []byte(certificateAuthorityData)

		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
			return nil, fmt.Errorf("no certs found in root CA file")
		}
	}

	if clientCertificateData != "" && clientKeyData != "" {
		cert, err := tls.X509KeyPair([]byte(clientCertificateData), []byte(clientKeyData))
		if err != nil {
			return nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	tlsConfig.InsecureSkipVerify = insecureSkipTLSVerify

	return &tlsConfig, nil
}

// AWSGetClusters returns all EKS clusters from AWS.
func AWSGetClusters(accessKeyId, secretAccessKey, region string) (string, error) {
	var clusters []*eks.Cluster
	var names []*string
	var nextToken *string

	cred := credentials.NewStaticCredentials(accessKeyId, secretAccessKey, "")

	sess, err := session.NewSession(&aws.Config{Region: aws.String(region), Credentials: cred})
	if err != nil {
		return "", err
	}

	eksClient := eks.New(sess)

	for {
		c, err := eksClient.ListClusters(&eks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return "", err
		}

		names = append(names, c.Clusters...)

		if c.NextToken == nil {
			break
		}

		nextToken = c.NextToken
	}

	for _, name := range names {
		cluster, err := eksClient.DescribeCluster(&eks.DescribeClusterInput{Name: name})
		if err != nil {
			return "", err
		}

		if *cluster.Cluster.Status == eks.ClusterStatusActive {
			clusters = append(clusters, cluster.Cluster)
		}
	}

	if clusters != nil {
		b, err := json.Marshal(clusters)
		if err != nil {
			return "", err
		}

		return string(b), nil
	}

	return "", nil
}

// AWSGetToken returns a bearer token for Kubernetes API requests.
// See: https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/7547c74e660f8d34d9980f2c69aa008eed1f48d0/pkg/token/token.go#L310
func AWSGetToken(accessKeyId, secretAccessKey, region, clusterID string) (string, error) {
	cred := credentials.NewStaticCredentials(accessKeyId, secretAccessKey, "")

	sess, err := session.NewSession(&aws.Config{Region: aws.String(region), Credentials: cred})
	if err != nil {
		return "", err
	}

	stsClient := sts.New(sess)

	request, _ := stsClient.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	request.HTTPRequest.Header.Add("x-k8s-aws-id", clusterID)
	presignedURLString, err := request.Presign(60)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`{"token": "k8s-aws-v1.%s"}`, base64.RawURLEncoding.EncodeToString([]byte(presignedURLString))), nil
}

// AzureGetClusters return all Kubeconfigs for all AKS clusters for the provided subscription and resource group.
func AzureGetClusters(subscriptionID, clientID, clientSecret, tenantID, resourceGroupName string, admin bool) (string, error) {
	ctx := context.Background()
	client := containerservice.NewManagedClustersClient(subscriptionID)

	authorizer, err := getAzureAuthorizer(clientID, clientSecret, tenantID)
	if err != nil {
		return "", err
	}
	client.Authorizer = authorizer

	var clusters []string

	for list, err := client.ListComplete(ctx); list.NotDone(); err = list.Next() {
		if err != nil {
			return "", err
		}

		var res containerservice.CredentialResults
		name := *list.Value().Name

		if admin {
			res, err = client.ListClusterAdminCredentials(ctx, resourceGroupName, name)
			if err != nil {
				return "", err
			}
		} else {
			res, err = client.ListClusterUserCredentials(ctx, resourceGroupName, name)
			if err != nil {
				return "", err
			}
		}

		for _, kubeconfig := range *res.Kubeconfigs {
			var kubeconfigJSON interface{}
			err := yaml.Unmarshal(*kubeconfig.Value, &kubeconfigJSON)
			if err != nil {
				return "", err
			}

			kubeconfigJSON = convert(kubeconfigJSON)
			kubeconfigJSONString, err := json.Marshal(kubeconfigJSON)
			if err != nil {
				return "", err
			}

			clusters = append(clusters, fmt.Sprintf("{\"name\": \"%s_%s_%s\", \"kubeconfig\": %s}", *kubeconfig.Name, resourceGroupName, name, kubeconfigJSONString))
		}
	}

	return fmt.Sprintf("[%s]", strings.Join(clusters, ",")), nil
}

func getAzureAuthorizer(clientID, clientSecret, tenantID string) (autorest.Authorizer, error) {
	oauthConfig, err := adal.NewOAuthConfig("https://login.microsoftonline.com/", tenantID)
	if err != nil {
		return nil, err
	}

	token, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return nil, err
	}

	return autorest.NewBearerAuthorizer(token), nil
}

// convert the map[interface{}]interface{} returned from yaml.Unmarshal to a map[string]interface{} for the usage in json.Marshal.
// See: https://stackoverflow.com/a/40737676
func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

// OIDCGetLink returns the link for the configured OIDC provider. The Link can then be used by the user to login.
func OIDCGetLink(discoveryURL, clientID, clientSecret, redirectURL string) (string, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return "", err
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	return fmt.Sprintf("{\"url\": \"%s\"}", oauth2Config.AuthCodeURL("", oauth2.AccessTypeOffline, oauth2.ApprovalForce)), nil
}

func OIDCGetRefreshToken(discoveryURL, clientID, clientSecret, redirectURL, code string) (string, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return "", err
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("could not get id token")
	}

	return fmt.Sprintf("{\"id_token\": \"%s\", \"refresh_token\": \"%s\", \"access_token\": \"%s\", \"expiry\": %d}", idToken, oauth2Token.RefreshToken, oauth2Token.AccessToken, oauth2Token.Expiry.Unix()), nil
}

// OIDCGetAccessToken is used to retrieve an access token from a refresh token.
func OIDCGetAccessToken(discoveryURL, clientID, clientSecret, redirectURL, refreshToken string) (string, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return "", err
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	ts := oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := ts.Token()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("{\"id_token\": \"%s\", \"refresh_token\": \"%s\", \"access_token\": \"%s\", \"expiry\": %d}", token.Extra("id_token"), token.RefreshToken, token.AccessToken, token.Expiry.Unix()), nil
}
