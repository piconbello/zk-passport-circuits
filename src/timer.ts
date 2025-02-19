import logUpdate from "log-update";
import chalk from "chalk";

const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const CHECK_MARK = "✓";
const CROSS_MARK = "✗";

type LogFunction = <T>(message: string, fn: () => Promise<T>) => Promise<T>;

interface Task {
  message: string;
  startTime: number;
  endTime?: number;
  status: "running" | "done" | "error";
}

const tasks: Task[] = [];
let spinnerIndex = 0;
let intervalId: NodeJS.Timer | null = null;

const formatDuration = (seconds: number): string => {
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.floor(seconds % 60);

  if (minutes > 0) {
    return `${minutes}m${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
};

const getTaskDisplay = (task: Task): string => {
  const duration = task.endTime
    ? (task.endTime - task.startTime) / 1000
    : (Date.now() - task.startTime) / 1000;

  const formattedDuration = formatDuration(duration);

  const status =
    task.status === "running"
      ? chalk.yellow(spinnerFrames[spinnerIndex])
      : task.status === "done"
        ? chalk.green(CHECK_MARK)
        : chalk.red(CROSS_MARK);

  return `${chalk.blue(task.message)}... ${chalk.cyan(formattedDuration)} ${status}`;
};

const updateDisplay = () => {
  spinnerIndex = (spinnerIndex + 1) % spinnerFrames.length;

  // Find the last running task (if any)
  const lastRunningTaskIndex = [...tasks]
    .reverse()
    .findIndex((t) => t.status === "running");

  if (lastRunningTaskIndex === -1) {
    // If no running tasks, just display all completed tasks
    const finalOutput = tasks.map(getTaskDisplay).join("\n");
    logUpdate(finalOutput);
    stopUpdating();
    return;
  }

  // Split tasks into completed and current
  const reversedIndex = tasks.length - 1 - lastRunningTaskIndex;
  const completedTasks = tasks.slice(0, reversedIndex);
  const currentTasks = tasks.slice(reversedIndex);

  // Render completed tasks normally and current tasks with updates
  const output = [
    ...completedTasks.map(getTaskDisplay),
    ...currentTasks.map(getTaskDisplay),
  ].join("\n");

  logUpdate(output);
};

const startUpdating = () => {
  if (intervalId === null) {
    intervalId = setInterval(updateDisplay, 80);
  }
};

const stopUpdating = () => {
  if (intervalId !== null) {
    clearInterval(intervalId);
    intervalId = null;
    logUpdate.done();
  }
};

export const time: LogFunction = async (message, fn) => {
  const task: Task = {
    message,
    startTime: Date.now(),
    status: "running",
  };

  tasks.push(task);
  startUpdating();

  try {
    const result = await fn();
    task.status = "done";
    task.endTime = Date.now();
    return result;
  } catch (error) {
    task.status = "error";
    task.endTime = Date.now();
    throw error;
  }
};
