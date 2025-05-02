import { Signale } from "signale";

export const log = new Signale({
  types: {
    start: {
      badge: "🔵",
      label: "started",
      color: "blue",
    },
    finish: {
      badge: "🟢",
      label: "finished",
      color: "green",
    },
  },
});

log.config({
  displayTimestamp: true,
});
