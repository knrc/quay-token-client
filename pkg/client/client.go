package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	csrfToken           = "/csrf_token"
	loginEndpoint       = "/api/v1/signin"
	serviceKeyPath      = "/keys/services/%s/keys/%s"
	approveKeyPath      = "/api/v1/superuser/approvedkeys/%s"
	deleteKeyPath       = "/api/v1/superuser/keys/%s"
	getUserPath         = "/api/v1/superuser/users/%s"
	dockerV2AuthPath    = "/v2/auth"
	dockerV2CatalogPath = "/v2/_catalog"
)

var ErrServiceKeyNotFound error = errors.New("service key not found")
var ErrServiceKeyNotApproved error = errors.New("service key not approved")
var ErrServiceKeyExpired error = errors.New("service key expired")

// Config holds the client configuration
type Config struct {
	QuayURL  string
	Username string
	Password string
}

// Client represents the Quay API client
type Client struct {
	Config     Config
	HTTPClient *http.Client
	CSRFToken  string
}

type CSRFResponse struct {
	CSRFToken string `json:"csrf_token"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool `json:"success"`
}

type ApproveTokenRequest struct {
	Notes string `json:"notes"`
}

// DockerAccessClaim represents a single access claim for Docker V2 JWT
type DockerAccessClaim struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// DockerV2Claims extends jwt.Claims with Docker V2 specific access claims and quay specific context
type DockerV2Claims struct {
	jwt.Claims
	Access  []DockerAccessClaim `json:"access"`
	Context map[string]any      `json:"context"`
}

// DockerCatalogResponse represents the response from the Docker V2 /_catalog endpoint
type DockerCatalogResponse struct {
	Repositories []string `json:"repositories"`
}

// GetUserResponse represents the response from the superuser getUser endpoint
type GetUserResponse struct {
	UUID     string  `json:"uuid"`
	Username string  `json:"username"`
	Email    *string `json:"email,omitempty"`
	Verified *bool   `json:"verified,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

// NewClient creates a new Quay API client
func NewClient(cfg Config) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	return &Client{
		Config: cfg,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
		},
	}, nil
}

// Get initial CSRF token
func (c *Client) GetCSRF() error {
	csrfTokenURL := c.Config.QuayURL + csrfToken
	response := &CSRFResponse{}
	err := c.handleRequest(csrfTokenURL, "GET", nil, nil, response, nil)
	if err != nil {
		return fmt.Errorf("failed to get csrf: %w", err)
	}
	c.CSRFToken = response.CSRFToken
	log.Printf("CSRF Token: %s", c.CSRFToken)

	return nil
}

// Performs login and obtain bearer and CSRF tokens
func (c *Client) Login() error {
	loginURL := c.Config.QuayURL + loginEndpoint
	request := &LoginRequest{
		Username: c.Config.Username,
		Password: c.Config.Password,
	}
	response := &LoginResponse{}

	err := c.handleRequest(loginURL, "POST", request, nil, response, nil)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	if !response.Success {
		return errors.New("failed to login, received unsuccessful response from service")
	}

	return nil
}

// GetServiceKey retrieves a service key from quay
func (c *Client) GetServiceKey(serviceName, keyID string) (*jose.JSONWebKey, error) {
	getKeyURL := c.Config.QuayURL + fmt.Sprintf(serviceKeyPath, serviceName, keyID)
	statusCodeErrors := map[int]error{
		http.StatusNotFound:  ErrServiceKeyNotFound,
		http.StatusConflict:  ErrServiceKeyNotApproved,
		http.StatusForbidden: ErrServiceKeyExpired,
	}

	response := &jose.JSONWebKey{}
	err := c.handleRequest(getKeyURL, "GET", nil, nil, response, statusCodeErrors)
	switch err {
	case nil:
		return response, nil
	case ErrServiceKeyNotFound:
		return nil, nil
	case ErrServiceKeyNotApproved:
		log.Println("Key exists but is not approved")
		return nil, err
	case ErrServiceKeyExpired:
		log.Println("Key exists but has expired")
		return nil, err
	default:
		return nil, fmt.Errorf("get service key request failed: %w", err)
	}
}

// GenerateRSAKeyPair generates a new RSA private and public key pair
func GenerateRSAKeyPair() (*rsa.PrivateKey, *jose.JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	publicJWK := &jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}

	return privateKey, publicJWK, nil
}

// CreateServiceKey sends the public key to Quay to create a service key
func (c *Client) CreateServiceKey(serviceName, keyID string, expiry time.Duration, privateKey *rsa.PrivateKey, publicJWK *jose.JSONWebKey) error {
	createKeyURL := c.Config.QuayURL + fmt.Sprintf(serviceKeyPath, serviceName, keyID)
	if expiry > 0 {
		createKeyURL += "?expiration=" + time.Now().Add(expiry).Format(time.RFC3339)
	}

	// Generate JWT
	jwtString, err := c.generateJWT(privateKey, keyID, serviceName)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + jwtString,
	}

	err = c.handleRequest(createKeyURL, "PUT", publicJWK, headers, nil, nil)
	if err != nil {
		return fmt.Errorf("create service key request failed: %w", err)
	}
	log.Printf("Service key '%s' for service '%s' created successfully.", keyID, serviceName)
	return nil
}

func (c *Client) generateJWT(privateKey *rsa.PrivateKey, keyID string, serviceName string) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", keyID))
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	claims := &jwt.Claims{
		Issuer:    serviceName,
		Subject:   keyID,
		Audience:  []string{c.Config.QuayURL},
		Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
	}

	jwtString, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}
	return jwtString, nil
}

// generateDockerV2JWT generates a Docker V2 compatible JWT
func (c *Client) GenerateDockerV2JWT(privateKey *rsa.PrivateKey, serviceName, keyID, username, scope string) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithHeader("kid", keyID))
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	user, err := c.GetUser(username)
	if err != nil {
		return "", fmt.Errorf("failed to get user ID from registry: %w", err)
	}

	var accessClaims []DockerAccessClaim
	// Example scope format: "repository:samuser/samrepo:pull,push"
	// KEV: This parsing is basic and might need changing depending on other server requirements
	scopeParts := strings.Split(scope, ":")
	if len(scopeParts) == 3 {
		accessClaims = append(accessClaims, DockerAccessClaim{
			Type:    scopeParts[0],
			Name:    scopeParts[1],
			Actions: strings.Split(scopeParts[2], ","),
		})
	} else {
		return "", fmt.Errorf("invalid scope format for Docker V2 JWT: %s", scope)
	}

	prefixes := []string{"http://", "https://"}

	audience := c.Config.QuayURL
	for _, prefix := range prefixes {
		var found bool
		audience, found = strings.CutPrefix(audience, prefix)
		if found {
			break
		}
	}
	claims := &DockerV2Claims{
		Claims: jwt.Claims{
			Issuer:    serviceName,
			Subject:   username,
			Audience:  []string{audience},
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
		},
		Access: accessClaims,
		// KEV: matches database user information
		Context: map[string]any{
			"kind":             "user",
			"user":             username,
			"entity_kind":      "user",
			"entity_reference": user.UUID,
		},
	}

	jwtString, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to generate Docker V2 JWT: %w", err)
	}
	return jwtString, nil
}

// ListRepositories lists repositories using the Docker V2 JWT
func (c *Client) ListRepositories(dockerToken string) (*DockerCatalogResponse, error) {
	listRepoURL := c.Config.QuayURL + dockerV2CatalogPath
	headers := map[string]string{
		"Authorization": "Bearer " + dockerToken,
	}
	response := &DockerCatalogResponse{}
	err := c.handleRequest(listRepoURL, "GET", nil, headers, response, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	return response, nil
}

// ApproveServiceKey approves a service key using the superuser endpoint
func (c *Client) ApproveServiceKey(keyID string) error {
	approveKeyURL := c.Config.QuayURL + fmt.Sprintf(approveKeyPath, keyID)

	request := &ApproveTokenRequest{
		Notes: "Automatically approved by quor token workflow at " + time.Now().String(),
	}
	err := c.handleRequest(approveKeyURL, "POST", request, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("approve service key request failed: %w", err)
	}

	log.Printf("Service key '%s' approved successfully.", keyID)
	return nil
}

// DeleteServiceKey deletes an existing service key
func (c *Client) DeleteServiceKey(keyID string) error {
	deleteKeyURL := c.Config.QuayURL + fmt.Sprintf(deleteKeyPath, keyID)

	err := c.handleRequest(deleteKeyURL, "DELETE", nil, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("delete service key request failed: %w", err)
	}
	log.Printf("Service key '%s' deleted successfully.", keyID)
	return nil
}

// GetUser retrieves information about the user using the superuser endpoint
func (c *Client) GetUser(username string) (*GetUserResponse, error) {
	getUserURL := c.Config.QuayURL + fmt.Sprintf(getUserPath, username)

	response := &GetUserResponse{}
	err := c.handleRequest(getUserURL, "GET", nil, nil, response, nil)
	if err != nil {
		return nil, fmt.Errorf("get user request failed: %w", err)
	}

	return response, nil
}

func (c *Client) handleRequest(requestUrl string, method string, payload any, headers map[string]string, response any, statusCodeErrors map[int]error) error {
	var requestBody io.Reader
	if payload != nil {
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
		requestBody = bytes.NewBuffer(jsonPayload)
	}

	req, err := http.NewRequest(method, requestUrl, requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "quay-token-client")
	if c.CSRFToken != "" {
		req.Header.Set("X-CSRF-Token", c.CSRFToken)
	}
	for hk, kv := range headers {
		req.Header.Set(hk, kv)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if response != nil {
			if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
		} else {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Printf("Empty response, but getting %s\n", string(bodyBytes))
		}
		fallthrough
	case http.StatusCreated:
	case http.StatusNoContent:
	case http.StatusAccepted:
		// Get next CSRF token
		csrfToken := resp.Header.Get("X-Next-Csrf-Token")
		if csrfToken != "" {
			c.CSRFToken = csrfToken
		}
		log.Printf("CSRF Token: %s", c.CSRFToken)
	default:
		if statusCodeErrors != nil {
			if err := statusCodeErrors[resp.StatusCode]; err != nil {
				return err
			}
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
