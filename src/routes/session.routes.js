
  import { Router } from "express";
import { isLoggedIn } from "../middlewares/auth.middleware.js";
import { getAllSessions, logoutFromSpecificSession } from "../controllers/session.controllers.js";
  
  const router = Router();
  
  router.get("/", isLoggedIn, getAllSessions);
  router.delete("/:id", isLoggedIn, logoutFromSpecificSession);
  
  export default router;