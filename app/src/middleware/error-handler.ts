import { Elysia } from "elysia";

export const errorHandler = new Elysia({ name: "error-handler" })
  .onError(({ error, set, code }) => {
    console.error("Error occurred:", error);

    switch (code) {
      case "VALIDATION":
        set.status = 400;
        return {
          error: "Validation failed",
          details: error.message
        };

      case "NOT_FOUND":
        set.status = 404;
        return {
          error: "Resource not found"
        };

      case "INTERNAL_SERVER_ERROR":
        set.status = 500;
        return {
          error: "Internal server error"
        };

      default:
        set.status = 500;
        return {
          error: "An unexpected error occurred"
        };
    }
  });
