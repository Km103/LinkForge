package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Km103/LinkForge/internal/config"
)

func FetchProfile(ctx context.Context, baseURL, activationCode, deviceName, platform string) (config.Client, error) {
	endpoint, err := enrollmentEndpoint(baseURL)
	if err != nil {
		return config.Client{}, err
	}
	if strings.TrimSpace(activationCode) == "" {
		return config.Client{}, errors.New("activation code is required")
	}
	body, err := json.Marshal(enrollmentRequest{
		Code:       activationCode,
		DeviceName: deviceName,
		Platform:   platform,
	})
	if err != nil {
		return config.Client{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return config.Client{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "LinkForge-enrollment/1")
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // Never forward an activation code to another origin.
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return config.Client{}, fmt.Errorf("enrollment request: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 128<<10)
	if response.StatusCode != http.StatusCreated {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(limited).Decode(&failure)
		if failure.Error == "" {
			failure.Error = response.Status
		}
		return config.Client{}, fmt.Errorf("enrollment rejected: %s", failure.Error)
	}
	var result enrollmentResponse
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return config.Client{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	if err := result.Profile.Validate(); err != nil {
		return config.Client{}, fmt.Errorf("server returned an invalid profile: %w", err)
	}
	return result.Profile, nil
}

func WriteProfile(path string, profile config.Client, replace bool) error {
	if err := PrepareProfilePath(path, replace); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".linkforge-profile-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(profile); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if replace {
		if err := os.Rename(tempPath, path); err != nil {
			return err
		}
	} else {
		// Linking within the same directory gives no-replace atomicity. The
		// activation response cannot silently overwrite another process's
		// profile between the preflight check and this commit.
		if err := os.Link(tempPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("profile already exists: %s", path)
			}
			return err
		}
		if err := os.Remove(tempPath); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	cleanup = false
	return os.Chmod(path, 0o600)
}

// PrepareProfilePath checks the destination before a one-time activation code
// is consumed and verifies that its parent directory is writable.
func PrepareProfilePath(path string, replace bool) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("profile output path is required")
	}
	if !replace {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("profile already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".linkforge-write-check-*")
	if err != nil {
		return err
	}
	name := file.Name()
	closeErr := file.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

func enrollmentEndpoint(baseURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("enrollment URL: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("enrollment URL cannot contain credentials, query parameters, or a fragment")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("enrollment URL must use HTTPS (HTTP is allowed only for loopback testing)")
		}
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("enrollment URL host is required")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/enroll"
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
