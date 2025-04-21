package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/cors"
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

type Task struct {
	ID   string
	Name string
}

type Config struct {
	ProjectTasksID      string
	PomodoroSessionDbId string
	ProjectsDbId        string
	NotionAPIKey        string
	Port                string
}

func loadConfig() (*Config, error) {
	projectTasksID := os.Getenv("PROJECT_TASKS_DB_ID")
	notionAPIKey := os.Getenv("NOTION_API_KEY")
	pomodoroSessionDbId := os.Getenv("POMODORO_SESSIONS_DB_ID")
	projectsDbId := os.Getenv("PROJECTS_DB_ID")
	port := os.Getenv("PORT")

	if projectTasksID == "" || notionAPIKey == "" || pomodoroSessionDbId == "" || projectsDbId == "" {
		return nil, fmt.Errorf("PROJECT_TASKS_DB_ID, NOTION_API_KEY, POMODORO_SESSIONS_DB_ID and PROJECTS_DB_ID must be set")
	}

	if port == "" {
		port = "5000"
	}

	return &Config{
		ProjectTasksID:      projectTasksID,
		NotionAPIKey:        notionAPIKey,
		PomodoroSessionDbId: pomodoroSessionDbId,
		ProjectsDbId:        projectsDbId,
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

func handleDisplaySummary(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// logger := slog.Default().With("handler", "display-summary")

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     getLogLevelFromEnv().Level(),
			AddSource: true,
		}))

		logger.Info("request received")
		defer logger.Info("request completed")

		if r.Method != http.MethodGet {
			sendJSONResponse(w, http.StatusMethodNotAllowed, Response{
				Error: "method not allowed",
			})
			return
		}

		// Extract parameters from URL
		parsedURL, _ := url.Parse(r.URL.String())
		date := parsedURL.Query().Get("date")
		showToday := parsedURL.Query().Get("today") == "true"

		if date == "" && !showToday {
			logger.Error("date parameter is missing and today is not true")
			http.Error(w, "either date parameter or today=true is required", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/markdown")

		// Handle today's tasks if requested
		if showToday {
			if err := displayTodaysTasks(w, cfg, logger); err != nil {
				logger.Error("failed to display today's tasks", "error", err)
				http.Error(w, "failed to display today's tasks", http.StatusInternalServerError)
				// return
			}
		}

		logger.Debug("Today's tasks has been fetched!")

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Step 1: Query Pomodoro Sessions for the given date
		sessionFilter := fmt.Sprintf(`{
			"filter": {
				"property": "Start Date",
				"date": {
					"equals": "%s"
				}
			}
		}`, date)

		sessions, err := queryNotionDatabase(ctx, cfg.PomodoroSessionDbId, sessionFilter, cfg.NotionAPIKey)
		if err != nil {
			logger.Error("failed to fetch pomodoro sessions", "error", err)
			http.Error(w, "failed to fetch pomodoro sessions", http.StatusInternalServerError)
			return
		}

		// Extract task IDs from sessions
		var taskIds []string
		for _, session := range sessions.Results {
			if relations, ok := session["properties"].(map[string]interface{})["Project Tasks"].(map[string]interface{})["relation"].([]interface{}); ok {
				for _, relation := range relations {
					if relMap, ok := relation.(map[string]interface{}); ok {
						taskIds = append(taskIds, relMap["id"].(string))
					}
				}
			}
		}

		if len(taskIds) == 0 {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "No tasks found for the given date")
			return
		}

		// Step 2: Fetch Project Tasks individually

		projectTaskMap := make(map[string]map[string]Task) // map[projectId]map[taskId]Task
		var projectIds []string
		seenProjectIds := make(map[string]bool)

		for _, taskId := range taskIds {
			task, err := getNotionPage(ctx, taskId, cfg.NotionAPIKey)
			if err != nil {
				logger.Error("failed to fetch project task", "taskId", taskId, "error", err)
				continue
			}

			props := task["properties"].(map[string]interface{})

			// Extract task name
			taskName := extractNotionTitle(props["Name"])

			// Extract project IDs
			if relations, ok := props["Projects"].(map[string]interface{})["relation"].([]interface{}); ok {
				for _, relation := range relations {
					if relMap, ok := relation.(map[string]interface{}); ok {
						projectId := relMap["id"].(string)
						if !seenProjectIds[projectId] {
							projectIds = append(projectIds, projectId)
							seenProjectIds[projectId] = true
							projectTaskMap[projectId] = make(map[string]Task)
						}
						projectTaskMap[projectId][taskId] = Task{
							ID:   taskId,
							Name: taskName,
						}

					}
				}
			}
		}

		if len(projectIds) == 0 {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "No projects found for the tasks")
			return
		}

		// Step 3: Fetch each project individually
		w.Header().Set("Content-Type", "text/plain")

		fmt.Fprintf(w, "**%s**\n\n", date)

		for _, projectId := range projectIds {
			project, err := getNotionPage(ctx, projectId, cfg.NotionAPIKey)
			if err != nil {
				logger.Error("failed to fetch project", "projectId", projectId, "error", err)
				continue
			}

			props := project["properties"].(map[string]interface{})
			projectName := extractNotionTitle(props["Name"])

			// Extract Project URL if it exists
			projectURL := ""
			if urlProp, ok := props["Project URL"].(map[string]interface{}); ok {
				if url, ok := urlProp["url"].(string); ok && url != "" {
					projectURL = url
				} else {
					logger.Debug("url key not found for Project URL property")
				}
			} else {
				logger.Debug("Project URL key not found")
			}

			// Display project name with URL if available
			if projectURL != "" {
				fmt.Fprintf(w, "[%s](%s)\n", projectName, projectURL)
			} else {
				fmt.Fprintf(w, "%s\n", projectName)
			}

			for _, taskName := range projectTaskMap[projectId] {
				fmt.Fprintf(w, "* %s\n", taskName.Name)
			}
			fmt.Fprintln(w) // Add a blank line between projects
		}
	}
}

func queryNotionDatabase(ctx context.Context, databaseId string, filter string, apiKey string) (*NotionPage, error) {
	req, err := http.NewRequestWithContext(ctx,
		"POST",
		fmt.Sprintf("https://api.notion.com/v1/databases/%s/query", databaseId),
		bytes.NewBuffer([]byte(filter)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Add("Notion-Version", "2022-06-28")
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var anyErr interface{}
		json.NewDecoder(resp.Body).Decode(&anyErr)
		return nil, fmt.Errorf("notion API error: %v", anyErr)
	}

	var result NotionPage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

func getNotionPage(ctx context.Context, pageId string, apiKey string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx,
		"GET",
		fmt.Sprintf("https://api.notion.com/v1/pages/%s", pageId),
		nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Add("Notion-Version", "2022-06-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var anyErr interface{}
		json.NewDecoder(resp.Body).Decode(&anyErr)
		return nil, fmt.Errorf("notion API error: %v", anyErr)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

func generateIDFilters(ids []string) string {
	var filters []string
	for _, id := range ids {
		filters = append(filters, fmt.Sprintf(`{
			"property": "id",
			"rich_text": {
				"equals": "%s"
			}
		}`, id))
	}
	return strings.Join(filters, ",")
}

func extractNotionTitle(titleProp interface{}) string {
	if title, ok := titleProp.(map[string]interface{}); ok {
		if titleArray, ok := title["title"].([]interface{}); ok && len(titleArray) > 0 {
			if titleItem, ok := titleArray[0].(map[string]interface{}); ok {
				if text, ok := titleItem["text"].(map[string]interface{}); ok {
					if content, ok := text["content"].(string); ok {
						return content
					}
				}
			}
		}
	}
	return "Untitled"
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
	mux.HandleFunc("/display-summary/", handleDisplaySummary(cfg))

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

func displayTodaysTasks(w http.ResponseWriter, cfg *Config, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Query for In Progress tasks
	taskFilter := `{
		"filter": {
			"property": "Status",
			"status": {
				"equals": "In Progress"
			}
		}
	}`

	tasks, err := queryNotionDatabase(ctx, cfg.ProjectTasksID, taskFilter, cfg.NotionAPIKey)
	if err != nil {
		return fmt.Errorf("failed to fetch in-progress tasks: %w", err)
	}

	if len(tasks.Results) == 0 {
		fmt.Fprintf(w, "**Today**\n\n*No tasks in progress*\n")
		return nil
	}

	// Map to store project tasks
	projectTaskMap := make(map[string]map[string]Task) // map[projectId]map[taskId]Task
	var projectIds []string
	seenProjectIds := make(map[string]bool)

	// Process each task
	for _, task := range tasks.Results {
		taskId := task["id"].(string)
		props := task["properties"].(map[string]interface{})
		taskName := extractNotionTitle(props["Name"])

		// Extract project IDs
		if relations, ok := props["Projects"].(map[string]interface{})["relation"].([]interface{}); ok {
			for _, relation := range relations {
				if relMap, ok := relation.(map[string]interface{}); ok {
					projectId := relMap["id"].(string)
					if !seenProjectIds[projectId] {
						projectIds = append(projectIds, projectId)
						seenProjectIds[projectId] = true
						projectTaskMap[projectId] = make(map[string]Task)
					}
					projectTaskMap[projectId][taskId] = Task{
						ID:   taskId,
						Name: taskName,
					}
				}
			}
		}
	}

	if len(projectIds) == 0 {
		fmt.Fprintln(w, "Today\n\nNo projects found for the tasks\n")
    return nil
  }

		// Display the results
		fmt.Fprintf(w, "**Today**\n\n")

		for _, projectId := range projectIds {
			project, err := getNotionPage(ctx, projectId, cfg.NotionAPIKey)
			if err != nil {
				logger.Error("failed to fetch project", "projectId", projectId, "error", err)
				continue
			}

			props := project["properties"].(map[string]interface{})
			projectName := extractNotionTitle(props["Name"])

			// Extract Project URL if it exists
			projectURL := ""
			if urlProp, ok := props["Project URL"].(map[string]interface{}); ok {
				if url, ok := urlProp["url"].(string); ok && url != "" {
					projectURL = url
				} else {
					logger.Debug("url key not found for Project URL property")
				}
			} else {
				logger.Debug("Project URL key not found")
			}

			// Display project name with URL if available
			if projectURL != "" {
				fmt.Fprintf(w, "[%s](%s)\n", projectName, projectURL)
			} else {
				fmt.Fprintf(w, "%s\n", projectName)
			}

			for _, taskName := range projectTaskMap[projectId] {
				fmt.Fprintf(w, "* %s\n", taskName.Name)
			}
			fmt.Fprintln(w) // Add a blank line between projects
		}


	fmt.Fprintln(w) // Add a blank line between sections
	return nil
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

func getLogLevelFromEnv() slog.Level {
	levelStr := os.Getenv("LOG_LEVEL")
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.Level(100) // Custom level higher than any standard level, so silent by default
	}
}
