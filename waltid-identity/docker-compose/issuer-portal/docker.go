package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerClient communicates with the Docker Engine API via the Unix socket.
var dockerClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", "/var/run/docker.sock")
		},
	},
	Timeout: 60 * time.Second,
}

// findContainerByService finds a container by its Docker Compose service name.
// Returns the container ID or empty string if not found.
func findContainerByService(serviceName string) (string, error) {
	// Use Docker API filters to find by compose service label
	filters := fmt.Sprintf(`{"label":["com.docker.compose.service=%s"]}`, serviceName)
	u := fmt.Sprintf("http://localhost/containers/json?filters=%s", url.QueryEscape(filters))

	resp, err := dockerClient.Get(u)
	if err != nil {
		return "", fmt.Errorf("list containers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
	}
	if err := json.Unmarshal(body, &containers); err != nil {
		return "", fmt.Errorf("parse containers: %w", err)
	}

	if len(containers) == 0 {
		return "", fmt.Errorf("no container found for service %q", serviceName)
	}

	name := containers[0].ID
	if len(containers[0].Names) > 0 {
		name = strings.TrimPrefix(containers[0].Names[0], "/")
	}
	log.Printf("Found container for service %q: %s", serviceName, name)
	return containers[0].ID, nil
}

// restartContainer restarts a Docker container by Compose service name
// and waits for it to be running again.
func restartContainer(serviceName string) error {
	containerID, err := findContainerByService(serviceName)
	if err != nil {
		return fmt.Errorf("find container: %w", err)
	}

	log.Printf("Restarting container %s (service: %s)", containerID[:12], serviceName)

	u := fmt.Sprintf("http://localhost/containers/%s/restart?t=5", containerID)
	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return fmt.Errorf("create restart request: %w", err)
	}

	resp, err := dockerClient.Do(req)
	if err != nil {
		return fmt.Errorf("restart container: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("restart returned status %d", resp.StatusCode)
	}

	log.Printf("Container restart initiated, waiting for it to be running...")

	// Poll for running state
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		if isContainerRunning(containerID) {
			log.Printf("Container %s is running", containerID[:12])
			return nil
		}
	}

	log.Printf("Container restart completed (health check timeout, proceeding)")
	return nil
}

// isContainerRunning checks if a container is in a running state.
func isContainerRunning(containerID string) bool {
	u := fmt.Sprintf("http://localhost/containers/%s/json", containerID)
	resp, err := dockerClient.Get(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var info struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false
	}

	return info.State.Running
}
