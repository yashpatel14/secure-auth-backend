import { logger } from "../logger/logger.js";
import { Session } from "../models/session.models.js";
import { Token } from "../models/token.models.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/core/ApiError.js";
import { ApiResponse } from "../utils/core/ApiResponse.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";
import { handleZodError } from "../utils/core/handleZodError.js";
import {
  emailVerificationMailgenContent,
  sendEmail,
} from "../utils/mail/mail.js";
import {
  generateAccessToken,
  generateRefreshToken,
  generateToken,
  hashToken,
} from "../utils/token.js";
import {
  validateEmail,
  validateLogin,
  validateRegister,
  validateResetPassword,
  validateVerifyEmail,
} from "../validations/auth.validations.js";

const register = asyncHandler(async (req, res) => {
  const { name, email, password } = handleZodError(validateRegister(req.body));

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    throw new ApiError(409, "Email is already registered");
  }

  const user = await User.create({
    name,
    email,
    password,
  });

  if (!user) {
    logger.warn("Failed to create user", { email });
    throw new ApiError(500, "Failed to create user");
  }

  const { unHashedToken, hashedToken, tokenExpiry } = generateToken();

  const token = await Token.create({
    user: user._id,
    tokenHash: hashedToken,
    type: "EMAIL_VERIFY",
    expiresAt: tokenExpiry,
  });

  if (!token) {
    logger.warn("Failed to create token", { email });
    throw new ApiError(500, "Failed to create token");
  }

  await sendEmail({
    email: user.email,
    subject: "Verify your email",
    mailgenContent: emailVerificationMailgenContent(
      username,
      `${process.env.CLIENT_URL}/verify-email?token=${encodeURIComponent(
        unHashedToken
      )}`
    ),
  });

  logger.info("Registration successful. Verification email sent.", {
    email,
    userId: user._id,
  });

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        user,
        "Registration successful. Verification email sent."
      )
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = handleZodError(validateLogin(req.body));

  logger.info("Login attempt", { email });

  const userAgent = req.header["user-agent"] || "";
  const ipAddress = req.ip || "";

  const user = await User.findOne({ email });

  if (!user) {
    logger.warn("User not found", { email });
    throw new ApiError(404, "User not found");
  }

  if (!user.emailVerified) {
    logger.warn("Email not verified", { email });
    throw new ApiError(401, "Email not verified");
  }

  const isPasswordCorrect = await user.isPasswordCorrect(password);

  if (!isPasswordCorrect) {
    logger.warn("Incorrect password", { email });
    throw new ApiError(401, "Incorrect password");
  }

  const session = await Session.create({
    user: user._id,
    ipAddress,
    userAgent,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
  });

  if (!session) {
    logger.warn("Failed to create session", { email });
    throw new ApiError(500, "Failed to create session");
  }

  const accessToken = generateAccessToken({
    id: user.id,
    sessionId: session._id,
    email: user.email,
    role: user.role,
  });

  const refreshToken = generateRefreshToken({
    id: user.id,
    sessionId: session._id,
    email: user.email,
    role: user.role,
  });

  const options = {
    httpOnly: true, // Set to false for testing
    secure: false, // Set to false for local development
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  };

  return res
    .status(201)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json(new ApiResponse(201, null, "Login successful"));
});

const logout = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    logger.warn("Logout attempt without refresh token");
  } else {
    try {
      const payload = verifyRefreshJWT(refreshToken);
      await Session.findByIdAndDelete(payload.sessionId);

      logger.info("Logout successful");
    } catch (error) {
      logger.warn("Logout attempt with invalid refresh token");
      throw new ApiError(401, "Invalid refresh token");
    }
  }

  const options = {
    httpOnly: true, // Set to false for testing
    secure: false, // Set to false for local development
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  };

  return res
    .status(200)
    .clearCookie("refreshToken", options)
    .clearCookie("accessToken", options)
    .json(new ApiResponse(200, null, "Logout successful"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = handleZodError(validateVerifyEmail(req.body));

  const hashToken = hashToken(token);

  const tokenDoc = await Token.findOne({ tokenHash: hashToken });

  if (!tokenDoc) {
    logger.warn("Invalid token");
    throw new ApiError(401, "Invalid token");
  }

  await User.findByIdAndUpdate(
    tokenDoc.userId,
    { emailVerified: true },
    { new: true }
  );

  await Token.findByIdAndDelete(tokenDoc._id);

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Email verified successfully"));
});

const resendVerificationEmail = asyncHandler(async (req, res) => {
  const { email } = handleZodError(validateEmail(req.body));

  logger.info("Resend verification email attempt", { email });

  const user = await User.findOne({ email });

  if (!user) {
    logger.warn("User not found", { email });
    throw new ApiError(404, "User not found");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Verification email sent successfully"));

  if (user.emailVerified) {
    logger.warn("Email already verified", { email });
    throw new ApiError(400, "Email already verified");
  }

  await Token.findOneAndDelete({ user: user._id, type: "EMAIL_VERIFY" });

  const { unHashedToken, hashedToken, tokenExpiry } = generateToken();

  const token = await Token.create({
    user: user._id,
    tokenHash: hashedToken,
    type: "EMAIL_VERIFY",
    expiresAt: tokenExpiry,
  });

  if (!token) {
    logger.warn("Failed to create token", { email });
    throw new ApiError(500, "Failed to create token");
  }

  await sendEmail({
    email: user.email,
    subject: "Verify your email",
    mailgenContent: emailVerificationMailgenContent(
      username,
      `${process.env.CLIENT_URL}/verify-email?token=${encodeURIComponent(
        unHashedToken
      )}`
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Verification email sent successfully"));
});

const forgotPassword = asyncHandler(async(req,res)=>{
    const {email} = handleZodError(validateEmail(req.body))

    const user = await User.findOne({email})

    if(!user){
        logger.warn("User not found", {email})
        throw new ApiError(404, "User not found")
    }

    await Token.findOneAndDelete({user:user._id, type:"FORGOT_PASSWORD"})

    const {unHashedToken, hashedToken, tokenExpiry} = generateToken()

    const token = await Token.create({
        user:user._id,
        tokenHash:hashedToken,
        type:"FORGOT_PASSWORD",
        expiresAt:tokenExpiry
    })

    await sendEmail({
        email: user?.email,
        subject: "Password reset request",
        mailgenContent: forgotPasswordMailgenContent(
          user.username,
          // ! NOTE: Following link should be the link of the frontend page responsible to request password reset
          // ! Frontend will send the below token with the new password in the request body to the backend reset password endpoint
          `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/reset-password?token=${encodeURIComponent(
            unHashedToken
          )}`
        ),
      });

      logger.info("Password reset request email sent", {email})

      return res.status(200).json(new ApiResponse(200, null, "Password reset request email sent successfully"))

})

const resetPassword = asyncHandler(async(req,res)=>{
    const {token, password} = handleZodError(validateResetPassword(req.body))

    const tokenHash = hashToken(token)

    const tokenDb = await Token.findOne({tokenHash, type:"FORGOT_PASSWORD",expiresAt:{$gt:Date.now()}})
    
    if(!tokenDb){
        logger.warn("Invalid token")
        throw new ApiError(401, "Invalid token")
    }

    const user = await User.findById(tokenDb.user)

    if(!user){
        logger.warn("User not found")
        throw new ApiError(404, "User not found")
    }

    const isPasswordCorrect = await isPasswordCorrect(password)

    if(!isPasswordCorrect){
        logger.warn("Invalid password")
        throw new ApiError(401, "Invalid password")
    }

    user.password = password

    await user.save()

    await Token.findByIdAndDelete(tokenDb._id)

    await Session.deleteMany({user:user._id})

    logger.info("Password reset successfully", {email:user.email})

    return res.status(200).json(new ApiResponse(200, null, "Password reset successfully"))

})

const deleteAccount = asyncHandler(async(req,res)=>{
    const user = req.user

    if(!user){
        logger.warn("User not found")
        throw new ApiError(404, "User not found")
    }

    logger.info("Request for account deletion", { email: user.email });

    const deletedUser = await User.findByIdAndDelete(user._id)

    if (!deletedUser) {
      logger.warn("Failed to delete user", { email: user.email });
      throw new ApiError(500, "Failed to delete user");
    }

    logger.info("User deleted successfully", { email: user.email });

    const options = {
    httpOnly: true, // Set to false for testing
    secure: false, // Set to false for local development
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  };

  return res
    .status(200)
    .clearCookie("refreshToken", options)
    .clearCookie("accessToken", options)
    .json(new ApiResponse(200, null, "Account deleted successfully"));

})

export { register, login, logout, verifyEmail, resendVerificationEmail, forgotPassword, resetPassword, deleteAccount };
