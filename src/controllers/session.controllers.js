import { logger } from "../logger/logger.js";
import { Session } from "../models/session.models.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";
import { transformSessions } from "../utils/sessions.js";


const getAllSessions = asyncHandler(async(req,res)=>{
    const user = req.user

    if(!user){
        throw new ApiError(401,"Unauthorized")
    }

    const currentSessionId = user.currentSessionId

    const allSessions = await Session.find({
        user:user._id
    })

    // Setting true flag to current session
  const allSesssionsWithCurrentFlag = allSessions.map((session) => ({
    ...session,
    current: session.id === currentSessionId,
  }));

  const formattedSessions = await transformSessions(
    allSesssionsWithCurrentFlag
  );


    return res
    .status(200)
    .json(new ApiResponse(200, formattedSessions, "User sessions fetched successfully"))

})

const logoutFromSpecificSession = asyncHandler(async(req,res)=>{
    const user = req.uses

    if(!user){
        throw new ApiError(401,"Unauthorized")
    }

    const sessionId = req.params.id

    if(!sessionId){
        throw new ApiError(400,"Session id is required")
    }

    const result = await Session.findByIdAndDelete(sessionId)

    if(result.lenght === 0){
        throw new ApiError(404,"Session not found")
    }

    logger.info("Session logged out successfully")

    return res
    .status(200)
    .json(new ApiResponse(200, null, "Session logged out successfully"))
})

export {
    getAllSessions,
    logoutFromSpecificSession}