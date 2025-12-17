import express from "express";
import pino from "pino";
import { pinoHttp } from "pino-http";
import cors from "cors";
import helmet from "helmet"
import cookieParser from "cookie-parser";


const app = express();

const isDev = process.env.NODE_ENV !== "production";
const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: isDev
    ? {
        target: "pino-pretty",
        options: {
          colorize: true,
          translateTime: "SYS:standard",
          ignore: "pid,hostname",
        },
      }
    : undefined,
});

app.use(
  pinoHttp({
    logger,
    autoLogging: true,
  })
);

app.use(helmet()); // security headers[web:237]

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "DELETE", "PUT", "PATCH"],
  })
);

if (process.env.IP_TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

app.get("/health", (req, res) => {
  req.log.info("Health check");
  res.json({ ok: true });
});

app.use((req, res) => {
  req.log.warn({ path: req.originalUrl }, "Route not found");
  res.status(404).json({ message: "Not found" });
});

app.use((err, req, res, next) => {
  req.log.error({ err }, "Unhandled error");
  const status = err.status || 500;
  res.status(status).json({
    message: err.message || "Internal server error",
  });
});

import authRouter from "./routes/auth.routes.js"
import adminRouter from "./routes/admin.routes.js"
import userRouter from "./routes/user.routes.js"
import sessionRouter from "./routes/session.routes.js"

app.use("/api/v1/auth", authRouter)
app.use("/api/v1/admin", adminRouter)
app.use("/api/v1/user", userRouter)
app.use("/api/v1/sessions", sessionRouter)

export { app, logger };
