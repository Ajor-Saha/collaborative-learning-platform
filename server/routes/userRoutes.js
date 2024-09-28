import { Router } from "express";
import {
    
    loginUser,
    logoutUser,
    register,
    verifyUser,
} from "../controllers/userController.js";
import { verifyJWT } from "../middleware/auth.middleware.js";

const router = Router();

router.post("/register", register);
router.put("/verifyUser", verifyUser);
router.post("/login", loginUser);
router.post("/logout", verifyJWT, logoutUser);


export default router;