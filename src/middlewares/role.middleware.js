import { ApiError } from "../utils/core/ApiError.js";
import { asyncHandler } from "../utils/core/asyncHandler.js";


export const isAdmin = asyncHandler(async(req,res,next)=>{
    if(!req.user){
        throw new ApiError(401,"Unauthorized")
    }


    const {role} = req.user

    if(role !== "admin"){
        throw new ApiError(403,"Forbidden")
    }

    next()
})