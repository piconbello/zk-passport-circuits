import readline from "readline";
import chalk from "chalk";

// Keep track of the last in-progress message
let lastInProgressMessage: string | null = null;
let lastLogOutput: string | null = null;

// Hook into console.log to detect if other messages are printed
const originalConsoleLog = console.log;
console.log = function (...args: any[]) {
  lastLogOutput = args.join(" ");
  originalConsoleLog.apply(console, args);
};

export async function time<T = any>(
  msg: string,
  func: () => Promise<T>,
): Promise<T> {
  // Show initial in-progress state
  const inProgressLine = `${chalk.gray("[......]")} ${chalk.blue(msg)}`;
  console.log(inProgressLine);
  lastInProgressMessage = msg;
  const startTime = Date.now();

  try {
    const result = await func();
    const duration = Date.now() - startTime;
    // Ensure at least 5 chars for seconds value + 2 for "s]"
    const secondsStr = (duration / 1000).toFixed(2).padStart(5, " ");
    const durationStr = `[${secondsStr}s]`;

    // Check if other logs have occurred since our in-progress message
    const canUpdateInPlace =
      lastLogOutput &&
      lastLogOutput.includes(`[......]`) &&
      lastLogOutput.includes(chalk.blue(msg));

    if (canUpdateInPlace) {
      // Move up one line and clear the in-progress line
      readline.moveCursor(process.stdout, 0, -1);
      readline.clearLine(process.stdout, 0);
    }

    // Show completion state
    console.log(`${chalk.gray(durationStr)} ${chalk.blue(msg)}`);
    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    // Ensure at least 6 chars for seconds value + 2 for "s]"
    const secondsStr = (duration / 1000).toFixed(2).padStart(5, " ");
    const durationStr = `[${secondsStr}s]`;

    // Check if other logs have occurred since our in-progress message
    const canUpdateInPlace =
      lastLogOutput &&
      lastLogOutput.includes(`[......]`) &&
      lastLogOutput.includes(chalk.blue(msg));

    if (canUpdateInPlace) {
      // Move up one line and clear the in-progress line
      readline.moveCursor(process.stdout, 0, -1);
      readline.clearLine(process.stdout, 0);
    }

    console.log(`${chalk.gray(durationStr)} ${chalk.blue(msg)}`);
    throw error;
  }
}
