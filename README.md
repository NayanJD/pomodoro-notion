# Pomodoro Notion

![pomodoro-notion-screenshot](https://github.com/NayanJD/pomodoro-notion/blob/main/assets/pomodoro-notion-screenshot.png)

(*Generated using Claude 3.7 Sonnet and ChatGpt 4o*)

Its a very simple pomodoro clock which uses a notion database to store the pomodoro sessions. I use Notion to do task management. 
The structure of it is `Projects` > `Projects Tasks` > `Pomodoro Sessions`. The `>` means there exists one `Relation` type column
in the child database. The basic columns for `Pomodoro Sessions` are: `Name`, `Project Tasks`, `Start Date`, `End Date`. The column
`Project Tasks` is a relation type to `Project Tasks` database.

## How to Run

1. Clone this repository.
2. Run the server
    1. Cd into server
    2. Using go >= 1.24.1, do `go mod tidy`
    3. Copy .env.example to .env and fill the values
    4. Run `source .env`
    5. Run `go run server.go` 
4. Open the client/pomodoro.html file in browser.
5. Your pomodoro clock is up 🥳

## Caveats

1. On page refresh, the timer would be lost.
2. The server should be kept on running or else, after the timer is stopped, the session would be lost.
   There is no background retry.

## Usage

To create a summary of work done yesterday and the tasks which are planned for today:

```bash
curl "http://localhost:5000/display-summary/?date=2025-03-31&today=true"
```

`date` param would pull items from Pomodoro Sessions notion database and create a report with Project tasks and Projects. `today` param would pull the Project tasks which are In Progress status.
