import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asynchandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import mongoose from "mongoose";
import jwt from "jsonwebtoken"
//mot using asynchandler here kyunki ye koi web req nhi h 
//yha wale methods hi internally use krne wale h 
const generateAccessAndRefreshTokens=async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        //access token to user
        //but refresh token is saved in db also 

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}
    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating refresh and access token ")

    }
}

const registerUser= asyncHandler(async(req,res)=>{
//get user details from frontend 
     const {fullname, email, username,password}=req.body // form/json 
    //  console.log("email: ",email);

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
   
    const existedUser=await User.findOne({
        $or:[{username},{email}]
    })
    if(existedUser){
        throw new ApiError(409,"User with this email or username already exists!")
    }
 //console.log(req.files);

//CHECK FOR IMAGES,AVATAR
    const avatarLocalPath =req.files?.avatar[0]?.path ;
   // const coverImageLocalPath=req.files?.coverImage[0]?.path;
    
   let coverImageLocalPath;
   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
    coverImageLocalPath=req.files.coverImage[0].path
   }
   
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
    username:username.toLowerCase()
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

const loginUser= asyncHandler(async(req,res)=>{
    //data from req.body 
    // Username or email 
    // find the user 
    // password check 
    // access and refresh token 
    // send the cookie 

    const {email,username,password}=req.body

    if(!username && !email){
        throw new ApiError(400,"username or email is required");
    }

    const user=await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User doesnt exist")
    }

    const isPasswordValid =await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Invalid User credentials")
    }

   const {accessToken , refreshToken} =await generateAccessAndRefreshTokens(user._id)

   const loggedInUser=await User.findById(user._id).select("-password -refreshToken")

   const options={
        httpOnly:true,
        secure:true
   }//now only server can modify the cookies

   return res
   .status(200)
   .cookie("accessToken",accessToken,options)
   .cookie("refreshToken",refreshToken,options)
   .json(
    new ApiResponse(
        200,
        {
            user:loggedInUser,accessToken,refreshToken
        },
        "User LoggedIn successfully"
    )
   )
})

const logoutUser=asyncHandler(async(req,res)=>{
    //refresh token clear kro 
    //clear cookies 
    //->our own middleware so that we can access user 
    await User.findByIdAndUpdate(
        req.user._id,
       { 
            $set:{
                refreshToken:undefined
            }
        },
        {
            new:true
        }
    
    )

    const options={
        httpOnly:true,
        secure:true
       }
    
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User Logged Out "))
})


//endpoint for refreshing accesstoken 
const refreshAccessToken=asyncHandler(async(req,res)=>{

    const incomingRefreshToken=req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorised Request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid refresh token")
        }
    
        if(incomingRefreshToken!==user?.refreshToken){
            throw new ApiError(401,"Refresh token is expired or used")
        }
        
        const options={
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken}=await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken:newRefreshToken},
                "Access Token refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh Token")
    }

})



//change password 
const changeCurrentPassword = asyncHandler(async(req,res)=>{
    const {oldPassword,newPassword}=req.body

    const user=await User.findById(req.user?.id)
    const isPasswordCorrect=await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid old Password")
    }

    user.password=newPassword
    await user.save({validateBeforeSave:false})

    return res
    .status(200)
    .json(new ApiResponse(200,{},"Password changed successfully"))
})

//CURRENT USER GET KRNA 
const getCurrentUser=asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(200,req.user,"Current user fetched successfully")
})



const updateAccountDetails= asyncHandler(async(req,res)=>{
    const {fullname,email}=req.body

    if(!fullname || !email){
        throw new ApiError(400,"All fields are required")

    }

    const user =User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullname,
                email:email,
            }
        },
        {new:true}//update hone k baad wali info return krega isse 
    
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"Account details updated successfully"))

})


//agr khi file update krvayein toh uske alg controllers rkhne chahie
//yha p multer,auth middleware lgana pdega

const updateUserAvatar=asyncHandler(async(req,res)=>{
    const avatarLocalPath=req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }

    const avatar=await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400,"Error while uploading on avatar ")
    }

    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar:avatar.url
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Avatar updated successfully")
    )
})

const updateUserCoverImage=asyncHandler(async(req,res)=>{
    //pehlle path lo user se
    const coverImageLocalPath=req.file?.path
    //path check kro aaya ya nhi 
    if(!coverImageLocalPath){
        throw new ApiError(400,"coverImage file is missing")
    }
    //path upload kro cloudinary p
    const coverImage=await uploadOnCloudinary(coverImageLocalPath)

    //agr nhi hua upload toh error 
    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading on coverImage")
    }

    //now update actual model mei uploaded file ka url
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage:coverImage.url
            }
        },
        {new:true}
    ).select("-password") //password hide krdo

    //send response finally 
    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Cover image updated successfully")
    )
})



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}

