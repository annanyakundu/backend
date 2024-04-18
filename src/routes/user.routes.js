import { Router } from "express";
import { registerUser } from "../controllers/user.controller.js";
import upload from 'multer'

const router=Router();
router.route("/register").post(
    upload.fields([
        {
            name:"avatar",//same name should be used in frontend
            maxCount:1
        },
        {
            name:"coverImage",
            maxCount:1
        }
    ]),
    registerUser
)

export default router







