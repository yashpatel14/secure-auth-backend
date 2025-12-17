import mongoose, { Schema } from "mongoose";
import argon2 from "argon2";
import jwt from "jsonwebtoken"


const userSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 120,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    // bcrypt/argon2 hash only
    password: {
      type: String,
      select: false, // never return by default
    },

    emailVerified: {
      type: Boolean,
      default: false,
    },

    role: {
      type: String,
      enum: ["user", "admin", "manager"],
      default: "user",
      index: true,
    },

    provider: {
      type: String,
      enum: ["local", "google", "github"],
      default: "local",
    },

    providerId: {
      type: String,
      index: true,
    },

    avatar: {
      type: String,
      default:
        "https://res.cloudinary.com/dmnh10etf/image/upload/v1750270944/default_epnleu.png",
    },

    // used to invalidate all refresh tokens globally when rotated
    tokenVersion: {
      type: String,
      default: () => new mongoose.Types.ObjectId().toString(),
    },

    lastLoginAt: {
      type: Date,
    },

    // optional: lockout / security
    failedLoginCount: {
      type: Number,
      default: 0,
    },
    lockedUntil: {
      type: Date,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await argon2.hash(password, {
    type: argon2.argon2id,
    timeCost: 2,
    memoryCost: 19456,
    parallelism: 1,
    hashLength: 32,
  });
});

userSchema.methods.isPasswordCorrect = async function(password){
    return argon2.verify(password,this.password)
}



  


userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ role: 1 });

export const User = mongoose.model("User", userSchema);
