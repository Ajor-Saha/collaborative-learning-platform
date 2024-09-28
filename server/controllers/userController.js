import prisma from "../DB/db.config.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from 'uuid';
import dayjs from 'dayjs';
import { sendVerificationEmail } from "../utils/sendVerificationEmail.js";

export const register = async (req, res) => {
  const { name, email, password, bio, education, interest } = req.body;

  try {
    // Validate that required fields are provided
    if ([name, email, password].some((field) => !field || field.trim() === "")) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Name, email, and password are required"));
    }

    // Validate that interest, if provided, is an array of strings
    if (interest && (!Array.isArray(interest) || !interest.every(i => typeof i === 'string'))) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Interest must be an array of strings"));
    }

    // Check if the user already exists
    const findUser = await prisma.user.findUnique({
      where: { email: email },
    });

    if (findUser) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Email already taken. Please use another email."));
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a verification code
    const verifyCode = uuidv4().split('-')[0]; // Generate a simple verification code
    const verifyCodeExpiry = dayjs().add(15, 'minute').toISOString(); // Set expiry 15 minutes from now

    // Create the new user
    const newUser = await prisma.user.create({
      data: {
        name: name,
        email: email,
        password: hashedPassword,
        bio: bio || "", // Optional field with default empty string
        education: education || "", // Optional field with default empty string
        interest: interest || [], // Optional field with default empty array
        verifyCode: verifyCode,
        verifyCodeExpiry: verifyCodeExpiry,
        isVerified: false, // Initially set to false until verified
      },
    });

    // Send the verification email
    const emailResponse = await sendVerificationEmail(email, name, verifyCode);
    if (!emailResponse.success) {
      return res
        .status(500)
        .json(new ApiResponse(false, 500, {}, "User created but failed to send verification email"));
    }

    // Exclude password and verification code from the response
    const { password: _, verifyCode: __, verifyCodeExpiry: ___, ...userWithoutSensitiveData } = newUser;

    return res
      .status(201)
      .json(
        new ApiResponse(
          true,
          201,
          userWithoutSensitiveData,
          "User registered successfully. Please check your email for the verification code."
        )
      );
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json(new ApiResponse(false, 500, null, "Internal Server Error"));
  }
};

export const verifyUser = async (req, res) => {
  const { email, verifyCode } = req.body;

  try {
    // Validate that email and verification code are provided
    if (!email || !verifyCode) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Email and verification code are required"));
    }

    // Find the user by email
    const user = await prisma.user.findUnique({
      where: { email: email },
    });

    if (!user) {
      return res
        .status(404)
        .json(new ApiResponse(false, 404, {}, "User not found"));
    }

    // Check if the user is already verified
    if (user.isVerified) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "User is already verified"));
    }

    // Check if the provided verification code matches the stored one
    if (user.verifyCode !== verifyCode) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Invalid verification code"));
    }

    // Check if the verification code has expired
    const currentTime = dayjs();
    if (currentTime.isAfter(dayjs(user.verifyCodeExpiry))) {
      return res
        .status(400)
        .json(new ApiResponse(false, 400, {}, "Verification code has expired"));
    }

    // If verification is successful, update the user's isVerified field
    const updatedUser = await prisma.user.update({
      where: { email: email },
      data: {
        isVerified: true,
      },
    });

    return res
      .status(200)
      .json(new ApiResponse(true, 200, {}, "User verified successfully"));
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json(new ApiResponse(false, 500, null, "Internal Server Error"));
  }
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate that all fields are provided
    if ([email, password].some((field) => !field || field.trim() === "")) {
      return res
        .status(400)
        .json(
          new ApiResponse(false, 400, {}, "Email and password are required")
        );
    }

    // Check if the user exists
    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      return res
        .status(401)
        .json(new ApiResponse(false, 401, {}, "Invalid email or password"));
    }

    if (!user.isVerified) {
      return res
        .status(401)
        .json(new ApiResponse(false, 401, {}, "Please verify your email first"));
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json(new ApiResponse(false, 401, {}, "Invalid email or password"));
    }

    // Generate JWT access token
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    // Exclude password from the response
    const { password: _, ...userWithoutPassword } = user;

    // Set the access token as a cookie
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true, // Ensure secure cookies
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res
      .status(200)
      .json(
        new ApiResponse(
          true,
          200,
          { user: userWithoutPassword, accessToken },
          "User logged in successfully"
        )
      );
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json(new ApiResponse(false, 500, null, "Internal Server Error"));
  }
};



// * Delete user


export const logoutUser = (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res
        .status(401)
        .json(new ApiResponse(false, 401, null, "Unauthorized request"));
    }

    // Clear the cookie
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: false, // Set to true if using HTTPS in production
      sameSite: "strict",
    });

    return res
      .status(200)
      .json(new ApiResponse(true, 200, null, "User logged out successfully"));
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json(new ApiResponse(false, 500, null, "Internal Server Error"));
  }
};


