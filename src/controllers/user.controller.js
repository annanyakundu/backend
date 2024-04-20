import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asynchandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";

//mot using asynchandler here kyunki ye koi web req nhi h 
//yha wale methods hi internally use krne wale h 
const generateAccessAndRefreshTokens=async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken =user.generateAccessToken()
        const refreshToken= user.generateRefreshToken()
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

    const {email,username,password}=req.body;

    if(!username || !email){
        throw new ApiError(400,"username or email is required");
    }

    const user=User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User doesnt exist")
    }

    const isPasswordValid =await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Invalid User credentials")
    }

   const{accessToken,refreshToken} =await generateAccessAndRefreshTokens(user._id)

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





export {
    registerUser,
    loginUser,
    logoutUser
}

