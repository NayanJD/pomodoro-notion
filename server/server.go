package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/rs/cors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

type Response struct {
	Error  string      `json:"error,omitempty"`
	Result interface{} `json:"results,omitempty"`
}

type SessionRequest struct {
	TaskId    string `json:"taskId"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}

type NotionPage struct {
	Object  string                   `json:"object"`
	Results []map[string]interface{} `json:"results"`
}

type Config struct {
	ProjectTasksID      string
	PomodoroSessionDbId string
	NotionAPIKey        string
	Port                string
}

func loadConfig() (*Config, error) {
	projectTasksID := os.Getenv("PROJECT_TASKS_DB_ID")
	notionAPIKey := os.Getenv("NOTION_API_KEY")
	pomodoroSessionDbId := os.Getenv("POMODORO_SESSIONS_DB_ID")
	port := os.Getenv("PORT")

	if projectTasksID == "" || notionAPIKey == "" || pomodoroSessionDbId == "" {
		return nil, fmt.Errorf("PROJECT_TASKS_DB_ID, NOTION_API_KEY and POMODORO_SESSIONS_DB_ID must be set")
	}

	if port == "" {
		port = "5000"
	}

	return &Config{
		ProjectTasksID:      projectTasksID,
		NotionAPIKey:        notionAPIKey,
		PomodoroSessionDbId: pomodoroSessionDbId,
		Port:                port,
	}, nil
}

func handleTasks(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.Default().With("handler", "tasks")

		logger.Info("received request")
		defer logger.Info("handled request")

		w.Header().Set("Content-Type", "application/json")

		// if r.Method == http.MethodOptions {
		// 	setupCorsResponse(w, r)
		// 	return
		// }

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
			bytes.NewBuffer([]byte(`{
        "filter": {
          "property": "Status",
          "status": {
            "equals": "In Progress"
          }
        }
      }`)))

		if err != nil {
			logger.Error("Error constructing the request", "err", err)
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
			logger.Error("Error while making request to notion", "err", err, "statusCode", resp.StatusCode)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "failed to fetch tasks from Notion",
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var anyErr interface{}
			json.NewDecoder(resp.Body).Decode(&anyErr)

			logger.Error("Non-200 response from Notion", "status", resp.StatusCode, "error", anyErr)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "received error response from Notion",
			})
			return
		}

		var notionResp NotionPage
		if err := json.NewDecoder(resp.Body).Decode(&notionResp); err != nil {
			logger.Error("Error while decoding json body", "err", err)
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

func handleSession(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.Default().With("handler", "log-session")

		logger.Info("received request")
		defer logger.Info("handled request")

		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodOptions {
			setupCorsResponse(w, r)
			return
		}

		if r.Method != http.MethodPost {
			sendJSONResponse(w, http.StatusMethodNotAllowed, Response{
				Error: "method not allowed",
			})
			return
		}

		sessionReqBody := SessionRequest{}

		err := json.NewDecoder(r.Body).Decode(&sessionReqBody)
		if err != nil {
			logger.Error("Error while decoding request body", "err", err)
			sendJSONResponse(w, http.StatusBadRequest, Response{
				Error: "failed to parse request body",
			})
			return
		}

		taskId := sessionReqBody.TaskId

		startTime, err := time.Parse(time.RFC3339, sessionReqBody.StartTime)
		if err != nil {
			logger.Error("Error while parsing start time date", "err", err)
			sendJSONResponse(w, http.StatusBadRequest, Response{
				Error: "failed to parse start time",
			})
			return
		}

		endTime, err := time.Parse(time.RFC3339, sessionReqBody.EndTime)
		if err != nil {
			logger.Error("Error while parsing start time date", "err", err)
			sendJSONResponse(w, http.StatusBadRequest, Response{
				Error: "failed to parse end time",
			})
			return
		}

		sessionBody := fmt.Sprintf(`{
        "parent": { "database_id": "%v" },
        "properties": {
          "Name": {
            "type": "title",
            "title": [
              {
                "text": {
                  "content": "Session-%v"
                }
              }
            ]
          },
          "Start Date": { "type": "date", "date": { "start": "%v" } },
          "End Date": { "type": "date", "date": { "start": "%v" } },
          "Project Tasks": { "type": "relation", "relation": [{ "id": "%v" }] }
        }
      }`, cfg.PomodoroSessionDbId, generateRandomString(6), startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), taskId)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx,
			"POST",
			"https://api.notion.com/v1/pages",
			bytes.NewBuffer([]byte(sessionBody)))
		if err != nil {
			logger.Error("Error constructing the request", "err", err)
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
			logger.Error("Error while making request to notion", "err", err, "statusCode", resp.StatusCode)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "failed to fetch tasks from Notion",
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var anyErr interface{}
			json.NewDecoder(resp.Body).Decode(&anyErr)

			logger.Error("Non-200 response from Notion", "status", resp.StatusCode, "error", anyErr)
			sendJSONResponse(w, http.StatusInternalServerError, Response{
				Error: "received error response from Notion",
			})
			return
		}

		var notionResp NotionPage
		if err := json.NewDecoder(resp.Body).Decode(&notionResp); err != nil {
			logger.Error("Error while decoding json body", "err", err)
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

func setupCorsResponse(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("Failed to load config", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tasks", handleTasks(cfg))
	mux.HandleFunc("/log-session", handleSession(cfg))

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodPost, http.MethodGet},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	})

	httpServer := &http.Server{
		Addr:    net.JoinHostPort("0.0.0.0", cfg.Port),
		Handler: cors.Handler(mux),
		// Handler:      mux,
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

func generateRandomString(length uint32) string {

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)

	rand.Read(b)

	for i, _ := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}
