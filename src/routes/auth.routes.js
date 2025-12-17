import { Router } from "express";
import { deleteAccount, forgotPassword, login, logout, register, resendVerificationEmail, resetPassword, verifyEmail } from "../controllers/auth.controllers.js";
import { authRateLimiter, forgotPasswordRateLimiter, resendVerificationRateLimiter } from "../middlewares/rateLimit.middleware.js";
import { isLoggedIn } from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/register").post(authRateLimiter,register)
router.route("/login").post(authRateLimiter,login)
router.route("/logout").post(logout)

router.post("/email/verify", verifyEmail);
router.post("/email/resend", resendVerificationRateLimiter,resendVerificationEmail);

router.post("/password/forgot", forgotPasswordRateLimiter,forgotPassword);
router.post("/password/reset", resetPassword);

router.post("/account/delete",isLoggedIn,deleteAccount)


export default router