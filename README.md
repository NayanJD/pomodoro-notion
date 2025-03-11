# Pomodoro Notion

![pomodoro-notion-screenshot](https://github.com/NayanJD/pomodoro-notion/blob/main/assets/pomodoro-notion-screenshot.png)

Its a very simple pomodoro clock which uses a notion database to store the pomodoro sessions. I use Notion to do task management. 
The structure of it is `Projects` > `Projects Tasks` > `Pomodoro Sessions`. The `>` means there exists one `Relation` type column
in the child database. The basic columns for `Pomodoro Sessions` are: `Name`, `Project Tasks`, `Start Date`, `End Date`. The column
`Project Tasks` is a relation type to `Proejct Tasks` database.
