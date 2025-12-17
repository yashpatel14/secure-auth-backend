import { app, logger } from "./app.js";
import connectDB from "./db/index.js";
import dotenv from "dotenv"


dotenv.config({
    path:"./.env"
})

const PORT = process.env.PORT || 8080;


connectDB()
.then(()=>{
    app.listen(PORT,()=>{
        logger.info(`🚀 Server running on port ${PORT}`);
    })
})
.catch(
    (err)=>{
        logger.error({ err }, "❌ Failed to start server");
    process.exit(1);
    }
)