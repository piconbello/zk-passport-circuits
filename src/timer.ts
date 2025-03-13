import logUpdate from "log-update";
import chalk from "chalk";

const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const CHECK_MARK = "✓";
const CROSS_MARK = "✗";

type LogFunction = <T>(message: string, fn: () => Promise<T>) => Promise<T>;

interface Task {
  id: string; // Add a unique ID to identify tasks
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

  // If no tasks, just exit
  if (tasks.length === 0) {
    stopUpdating();
    return;
  }

  // Check if any tasks are still running
  const hasRunningTasks = tasks.some((task) => task.status === "running");

  if (!hasRunningTasks) {
    // If no running tasks, display everything and stop updates
    const finalOutput = tasks.map(getTaskDisplay).join("\n");
    logUpdate(finalOutput);
    stopUpdating();
    return;
  }

  // Just render all tasks
  const output = tasks.map(getTaskDisplay).join("\n");
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

// Create a unique ID for tasks
const createTaskId = (message: string): string => {
  return `${message}_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
};

export const time: LogFunction = async (message, fn) => {
  // Check if we already have a task with this message
  const existingTaskIndex = tasks.findIndex(
    (task) => task.message === message && task.status === "running",
  );

  // If found, remove the existing task to avoid duplicates
  if (existingTaskIndex !== -1) {
    tasks.splice(existingTaskIndex, 1);
  }

  const task: Task = {
    id: createTaskId(message),
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
