import { Elysia } from "elysia";

export const errorHandler = new Elysia({ name: "error-handler" })
  .onError(({ error, set, code }) => {
    console.error("🚨 ERROR OCCURRED:");
    console.error("🚨 Code:", code);
    console.error("🚨 Error:", error);
    console.error("🚨 Error message:", error.message);
    console.error("🚨 Error stack:", error.stack);

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
        console.error("🚨 INTERNAL_SERVER_ERROR - Returning 500");
        set.status = 500;
        return {
          error: "Eroare internă de server"
        };

      default:
        console.error("🚨 DEFAULT ERROR - Returning 500");
        set.status = 500;
        return {
          error: "Eroare internă de server"
        };
    }
  });
