import { logger } from "../logger/logger.js";
import { Session } from "../models/session.models.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";
import { ApiError } from "../utils/core/ApiError.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessJWT,
  verifyRefreshJWT,
} from "../utils/token.js";

const isProd = process.env.NODE_ENV === "production";

export const isLoggedIn = asyncHandler(async (req, res, next) => {
  const { accessToken, refreshToken } = req.cookies || {};

  try {
    // No access token: try refresh token flow
    if (!accessToken) {
      if (!refreshToken) {
        throw new ApiError(401, "Unauthorized");
      }

      const payload = verifyRefreshJWT(refreshToken); // throws if invalid/expired

      const session = await Session.findById(payload.sessionId);
      if (!session) {
        throw new ApiError(401, "Unauthorized");
      }

      const incomingUserAgent = req.headers["user-agent"] || "";
      const incomingIpAddress = req.ip; // assuming trust proxy set

      if (
        session.userAgent !== incomingUserAgent ||
        session.ipAddress !== incomingIpAddress
      ) {
        await Session.findByIdAndDelete(session._id);
        logger.warn("Session mismatch. Please log in again", {
          sessionId: session._id,
        });
        throw new ApiError(401, "Session mismatch. Please log in again");
      }

      // Extend session expiry
      await Session.findByIdAndUpdate(session._id, {
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });

      // Rotate tokens
      const newAccessToken = generateAccessToken({
        id: session.user,
        sessionId: session._id,
        email: payload.email,
        role: payload.role,
      });

      const newRefreshToken = generateRefreshToken({
        id: session.user,
        sessionId: session._id,
        email: payload.email,
        role: payload.role,
      });

      res.cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "strict" : "lax",
        maxAge: 15 * 60 * 1000,
      });

      res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "strict" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      req.user = {
        id: session.user,
        email: payload.email,
        role: payload.role,
        sessionId: session._id,
      };
    } else {
      // Access token present: verify and pass through
      const payload = verifyAccessJWT(accessToken);
      req.user = payload;
    }

    return next();
  } catch (error) {
    // Clear cookies on any auth error
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
    });

    throw error;
  }
});
