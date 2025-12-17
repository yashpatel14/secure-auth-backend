import { hash, verify } from "argon2";


export const hashPassword = async (password) => {
    return await hash(password);
  };


  export const verifyPasswordHash = async (
    hash,
    password,
    type
  ) => {
    const isValid = await verify(hash, password);
    if (!isValid) {
      if (type === "login") {
        throw new ApiError(HttpStatus.UNAUTHORIZED, "Invalid credentials");
      }
      throw new ApiError(
        HttpStatus.BAD_REQUEST,
        "New password cannot be the same as the old password"
      );
    }
  };