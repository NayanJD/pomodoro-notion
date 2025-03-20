package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

type Response struct {
	Error  string      `json:"error,omitempty"`
	Result interface{} `json:"result,omitempty"`
}

type NotionPage struct {
	Object  string                   `json:"object"`
	Results []map[string]interface{} `json:"results"`
}

type Config struct {
	ProjectTasksID string
	NotionAPIKey   string
	Port           string
}

func loadConfig() (*Config, error) {
	projectTasksID := os.Getenv("PROJECT_TASKS_DB_ID")
	notionAPIKey := os.Getenv("NOTION_API_KEY")
	port := os.Getenv("PORT")

	if projectTasksID == "" || notionAPIKey == "" {
		return nil, fmt.Errorf("PROJECT_TASKS_DB_ID and NOTION_API_KEY must be set")
	}

	if port == "" {
		port = "5000"
	}

	return &Config{
		ProjectTasksID: projectTasksID,
		NotionAPIKey:   notionAPIKey,
		Port:           port,
	}, nil
}

func handleTasks(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			sendJSONResponse(w, http.StatusMethodNotAllowed, Response{
				Error: "method not allowed",
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx,
			"POST",
			fmt.Sprintf("https://api.notion.com/v1/databases/%s/query", cfg.ProjectTasksID),
			nil)
		if err != nil {
			slog.Error("Error constructing the request", "handler", "tasks", "err", err)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "failed to construct request",
			})

			return
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cfg.NotionAPIKey))
		req.Header.Add("Notion-Version", "2022-06-28")
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil || (resp != nil && resp.StatusCode >= 500 && resp.StatusCode < 600) {
			slog.Error("Error while making request to notion", "handler", "tasks", "err", err, "statusCode", resp.StatusCode)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "failed to fetch tasks from Notion",
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var anyErr interface{}
			json.NewDecoder(resp.Body).Decode(&anyErr)

			slog.Error("Non-200 response from Notion", "handler", "tasks", "status", resp.StatusCode, "error", anyErr)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "received error response from Notion",
			})
			return
		}

		var notionResp NotionPage
		if err := json.NewDecoder(resp.Body).Decode(&notionResp); err != nil {
			slog.Error("Error while decoding json body", "handler", "tasks", "err", err)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "failed to parse Notion response",
			})
			return
		}

		sendJSONResponse(w, http.StatusOK, Response{
			Result: notionResp.Results,
		})
	}
}

func sendJSONResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("Failed to encode response", "err", err)
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("Failed to load config", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tasks", handleTasks(cfg))

	httpServer := &http.Server{
		Addr:         net.JoinHostPort("0.0.0.0", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Starting server", "addr", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}
