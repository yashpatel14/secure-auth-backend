import { Router } from "express";
import { isLoggedIn } from "../middlewares/auth.middleware.js";
import { isAdmin } from "../middlewares/role.middleware.js";
import { getAllUsers, logoutUserSession } from "../controllers/admin.controllers.js";

const router = Router();


router.route("/users").get(isLoggedIn,isAdmin,getAllUsers)

router.route("/users/:userId/sessions").get(isLoggedIn,isAdmin,getAllUsers)
router.route("/users/sessions/:sessionId").delete(isLoggedIn,isAdmin,logoutUserSession)

export default router