export type TZ = "Local" | "UTC";

export function getTimeFormatter(tz: TZ, hour12: boolean): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: tz === "Local" ? undefined : tz,
    hour12,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: hour12 ? "h12" : "h23",
  });
}

export function getDateFormatter(tz: TZ): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: tz === "Local" ? undefined : tz,
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

export function formatTime(ts: number, tz: TZ, hour12: boolean): string {
  return getTimeFormatter(tz, hour12).format(new Date(ts));
}

export function formatDate(ts: number, tz: TZ, hour12: boolean): string {
  return getDateFormatter(tz).format(new Date(ts)) + " " + formatTime(ts, tz, hour12);
}
