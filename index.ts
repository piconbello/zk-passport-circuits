import { time } from "./src/timer";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// This is a deliberately poorly written function that blocks the main thread
const blockingOperation = () => {
  let result = 0;
  // Perform an expensive synchronous calculation
  for (let i = 0; i < 200000000; i++) {
    result += Math.sin(i) * Math.cos(i);
  }
  return result;
};

async function main() {
  try {
    await time("Preparing environment", async () => {
      await delay(2000);
    });

    await time("Installing dependencies", async () => {
      await delay(3000);
    });

    // This task will block the main thread
    await time("Performing heavy calculation", async () => {
      // Even though this is wrapped in an async function,
      // the blocking operation will freeze the spinner animation
      blockingOperation();
      await delay(1000); // Add a small delay to make it more noticeable
    });

    await time("Running tests", async () => {
      await delay(3000);
    });

    await time("Deploying", async () => {
      await delay(2000);
    });

    console.log("\nPipeline completed successfully!");
  } catch (error) {
    console.error("\nPipeline failed:", error);
  }
}

main();
