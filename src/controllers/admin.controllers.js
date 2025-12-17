import { logger } from "../logger/logger.js";
import { Session } from "../models/session.models.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/core/ApiError.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";


const getAllUsers = asyncHandler(async (req, res) => {
   
    const adminId = req.user?._id

    if(!adminId){
        throw new ApiError(401,"Unauthorized")
    }

    const user = await User.find(
        {$nq: {role:"admin",_id:adminId}},
        {
            name:1,
            email:1,
            role:1,
            createdAt:1,
            updatedAt:1,
            emailVerified: 1,
            avatar: 1,
            provider:1
        }
    ).sort({createdAt:-1}).lean()

    logger.info("Admin fetched all users successfully")
    return res.status(200).json(new ApiResponse(200, user, "Users fetched successfully"))
});

const logoutUserSession = asyncHandler(async(req,res)=>{
    const {sessionId} = req.params

    const session = await Session.findByIdAndDelete(sessionId)

    if(!session){
        throw new ApiError(404,"Session not found")
    }

    return res
    .status(200)
    .json(new ApiResponse(200, null, "User logged out successfully"))

})

const getUserSessionsById = asyncHandler(async(req,res)=>{
    const {userId} = req.params

    const allSession = await Session.aggregate([
        {
            $match: {
                user: userId
            }
        },
        {
            $lookup: {
                from: "users",
                localField: "user",
                foreignField: "_id",
                as: "user"
            }
        },
        {
            $unwind: "$user"
        },
        
    ])

    const formattedSessions = await transformSessions(allSession);

    return res
    .status(200)
    .json(new ApiResponse(200, formattedSessions, "User sessions fetched successfully"))
})

export {getAllUsers, logoutUserSession, getUserSessionsById}