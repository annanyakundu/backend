import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asynchandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";


const registerUser= asyncHandler(async(req,res)=>{
//get user details from frontend 
     const {fullname, username, email,password}=req.body // form/json 
     console.log("email: ",email);

//VALIDATIONN
    // if(fullname===""){
    //     throw new ApiError(400,"Fullname is Required")
    // }
    if(
        [fullname,email,username,password].some((field)=>field?.trim()==="")
    ){
            throw new ApiError(400,"All fields are required")
    }


//CHECK IF USER EXISTING OR NOT
   
    const existedUser=User.findOne({
        $or:[{username},{email}]
    })
    if(existedUser){
        throw new ApiError(409,"User with this email or username already exists!")
    }

//CHECK FOR IMAGES,AVATAR
    const avatarLocalPath =req.files?.avatar[0]?.path ;
    const coverImageLocalPath=req.files?.coverImage[0]?.path;
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required!")
    }

//UPLOAD THEM TO CLOUDINARY 
   const avatar= await uploadOnCloudinary(avatarLocalPath)
   const coverImage=await uploadOnCloudinary(coverImageLocalPath)
   if(!avatar){
   throw new ApiError(400,"Avatar file is required!")
   }   

//CREATE USER OBJECT- CREATE USER ENTRY IN db
   const user = await User.create({
    fullname,
    avatar:avatar.url,
    coverImage:coverImage?.url||"",
    email,
    password,
    username:username.toLoweCase()
   })

//REMOVE PASSWORD AND REFRESHTOKEN FIELD FROM RESPONSE 
   const createdUser=await User.findById(user._id).select(
    "-password -refreshToken"
   )

   if(!createdUser){
    throw new ApiError(500,"Something went wrong while regiistering the user")
   }

//RETURN RESPONSE 
   return res.status(201).json(
   new ApiResponse(200,createdUser,"USER REGISTERED SUCCESSFULLY")
   )


})
export {registerUser}

