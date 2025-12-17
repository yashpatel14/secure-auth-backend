import { logger } from "../logger/logger.js";
import { Session } from "../models/session.models.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";
import { handleZodError } from "../utils/core/handleZodError.js";
import { hashPassword } from "../utils/password.js";
import { validatePassword } from "../validations/auth.validations.js";


const getMe = asyncHandler(async(req,res)=>{
    const user = req.user

    if(!user){
        throw new ApiError(401,"Unauthorized")
    }

    const userDetails = await User.aggregate([
        {
            $match: {
                _id: user._id
            }
        },
        {
            $project: {
                name:1,
                email:1,
                role:1,
                createdAt:1,
                updatedAt:1,
                emailVerified: 1,
                avatar: 1,
                provider:1
            }
        }
    ])

    if(!userDetails){
        throw new ApiError(404,"User not found")
    }

    return res
    .status(200)
    .json(new ApiResponse(200, userDetails, "User details fetched successfully"))
})

const changePassword = asyncHandler(async(req,res)=>{
    const user = req.user

    if(!user){
        throw new ApiError(401,"Unauthorized")
    }

    const password  = handleZodError(validatePassword(req.body.password))

    const hashedPassword = await hashPassword(password)

    user.password = hashedPassword

    await user.save()

    await Session.deleteMany({user:user._id})

    logger.info("Password changed successfully")

    return res
    .status(200)
    .json(new ApiResponse(200, null, "Password changed successfully"))

})

const updateAvatar = asyncHandler(async(req,res)=>{

    const user = req.user

    if(!user){
        throw new ApiError(401,"Unauthorized")
    }

    let imageUrl = await uploadOnCloudinary(req.file?.path || "")
    logger.info("Image uploaded successfully")

    user.avatar = imageUrl.secure_url

    await user.save()

    logger.info("Avatar updated successfully")

    return res
    .status(200)
    .json(new ApiResponse(200, null, "Avatar updated successfully"))

}) 

export {getMe, changePassword, updateAvatar}
