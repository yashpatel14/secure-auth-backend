import { UAParser } from "ua-parser-js";
import { format } from "date-fns";
import { logger } from "../logger/logger.js";

export const transformSessions = async (sessions) => {
  const transformed = [];

  for (const session of sessions) {
    const parser = UAParser(session.userAgent);
    const browser = parser.browser.name || "Unknown Browser";
    const os = parser.os.name || "Unknown OS";
    const device = `${browser} on ${os}`;
    const location = await getLocationFromIP(session.ipAddress);
    const lastLogin = format(
      new Date(session.updatedAt),
      "MMM d, yyyy h:mm a"
    );

    const status = getSessionStatus(session.expiresAt);

    transformed.push({
      id: session._id,
      current: session.current,
      device,
      ip: session.ipAddress,
      lastLogin,
      location,
      status,
    });
  }
  return transformed;
};

async function getLocationFromIP(ipAddress) {
  if (ipAddress === "::1" || ipAddress === "127.0.0.1") return "Localhost";
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();

    const location =
      data.city && data.country
        ? `${data.city}, ${data.country}`
        : data.country || "Unknown Location";

    return location;
  } catch (error) {
    logger.error("Error fetching IP info", { error: error.message || "" });
    return "Unknown Location";
  }
}

function getSessionStatus(expiresAt) {
  return new Date() < new Date(expiresAt) ? "active" : "expired";
}
