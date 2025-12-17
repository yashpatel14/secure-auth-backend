// utils/handleZodError.js
import { ZodError } from "zod";
import { ApiError } from "./ApiError.js";



export const handleZodError = (result) => {
  if (result.success) return result.data;

  const issue = result.error?.issues[0];
  const path = issue?.path.join(".");
  const isMissing =
    issue?.code === "invalid_type" && issue.input === "undefined";

  throw new ApiError(
    isMissing ? 400 : 422,
    isMissing
      ? path
        ? `Missing '${path}' field`
        : "Missing required fields"
      : issue?.message || "Invalid input data"
  );
};
