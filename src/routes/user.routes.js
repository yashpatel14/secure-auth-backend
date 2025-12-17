
  import { Router } from "express";
import { isLoggedIn } from "../middlewares/auth.middleware.js";
import { changePassword, getMe, updateAvatar } from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
  
  const router = Router();
  
  router.get("/me", isLoggedIn, getMe);
  router.patch("/me/password", isLoggedIn, changePassword);
  router.patch("/me/avatar", isLoggedIn, upload.single("avatar"), updateAvatar);
  
  export default router;