import crypto from "crypto";
import jwt from "jsonwebtoken";

export const hashToken = (rawToken) =>
  crypto.createHash("sha256").update(rawToken).digest("hex");

export const generateToken = () => {
    const unHashedToken = crypto.randomBytes(20).toString("hex");
  
    // This should stay in the DB to compare at the time of verification
    const hashedToken = crypto
      .createHash("sha256")
      .update(unHashedToken)
      .digest("hex");
    // This is the expiry time for the token (20 minutes)
    const tokenExpiry = Date.now() + 20 * 60 * 1000; // 20 minutes;
  
    return { unHashedToken, hashedToken, tokenExpiry };

}


export const generateAccessToken = () =>{
    return jwt.sign(
        {
          _id: this._id,
          email: this.email,
          name: this.name,
          role:this.role,
          sessionId: this.sessionId
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRES },
      );
}

export const generateRefreshToken = () => {
    return jwt.sign(
      {
        _id: this._id,
          email: this.email,
          name: this.name,
          role:this.role,
          sessionId: this.sessionId
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRY },
    );
  };


  export const verifyAccessJWT = (accessToken) => {
    try {
        const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
        return payload
    } catch (error) {
        throw new ApiError(401, "Invalid access token");
    }
  }

  export const verifyRefreshJWT = (refreshToken) => {
    try {
        const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        return payload
    } catch (error) {
        throw new ApiError(401, "Invalid refresh token");
    }
  }