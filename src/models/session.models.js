import mongoose, { Schema } from "mongoose";

const sessionSchema = new Schema(
    {
      user: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true,
      },
  
      // hash of refresh token
      refreshToken: {
        type: String,
        required: true,
      },
  
      ipAddress: {
        type: String,
        required: true,
      },
  
      userAgent: {
        type: String,
        required: true,
      },
  
      expiresAt: {
        type: Date,
        required: true,
        index: true,
      },
  
      revokedAt: {
        type: Date,
      },
    },
    { timestamps: true }
  );
  
  // optional: limit to one session per device fingerprint
  sessionSchema.index(
    { user: 1, userAgent: 1, ipAddress: 1 },
    { unique: false } // set to true if you want strict single session per device
  );
  
  export const Session = mongoose.model("Session", sessionSchema);
  