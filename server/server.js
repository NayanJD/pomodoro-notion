require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const NOTION_API_KEY = process.env.NOTION_API_KEY;
const PROJECT_TASKS_DB_ID = process.env.PROJECT_TASKS_DB_ID;
const POMODORO_SESSIONS_DB_ID = process.env.POMODORO_SESSIONS_DB_ID;

// Fetch only "In Progress" tasks from Notion
app.get("/tasks", async (req, res) => {
  try {
    const response = await axios.post(
      `https://api.notion.com/v1/databases/${PROJECT_TASKS_DB_ID}/query`,
      {
        filter: {
          property: "Status",
          status: {
            equals: "In Progress",
          },
        },
      },
      {
        headers: {
          Authorization: `Bearer ${NOTION_API_KEY}`,
          "Notion-Version": "2022-06-28",
          "Content-Type": "application/json",
        },
      },
    );

    res.json({ results: response.data.results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Log a pomodoro session to Notion
app.post("/log-session", async (req, res) => {
  try {
    const { taskId, startTime, endTime } = req.body;
    const response = await axios.post(
      `https://api.notion.com/v1/pages`,
      {
        parent: { database_id: POMODORO_SESSIONS_DB_ID },
        properties: {
          Name: {
            type: "title",
            title: [
              {
                text: {
                  content: `Session ${Math.random().toString(36).substring(7)}`,
                },
              },
            ],
          },
          "Start Date": { type: "date", date: { start: startTime } },
          "End Date": { type: "date", date: { start: endTime } },
          "Project Tasks": { type: "relation", relation: [{ id: taskId }] },
        },
      },
      {
        headers: {
          Authorization: `Bearer ${NOTION_API_KEY}`,
          "Notion-Version": "2022-06-28",
        },
      },
    );

    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(5000, () => console.log("Server running on port 5000"));
