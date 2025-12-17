import mongoose, { Schema } from "mongoose";

const tokenSchema = new Schema(
    {
      user: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true,
      },
  
      // hash of random token (never raw)
      tokenHash: {
        type: String,
        required: true,
        unique: true,
      },
  
      type: {
        type: String,
        enum: ["EMAIL_VERIFY", "PASSWORD_RESET"],
        required: true,
        index: true,
      },
  
      expiresAt: {
        type: Date,
        required: true,
        index: true,
      },
  
      usedAt: {
        type: Date,
      },
    },
    { timestamps: true }
  );

  
  
  // optional compound index to find active tokens quickly
  tokenSchema.index({ user: 1, type: 1, expiresAt: 1 });
  
  export const Token = mongoose.model("Token", tokenSchema);
  