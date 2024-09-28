import "dotenv/config";
import cookieParser from "cookie-parser";
import express from "express";


const app = express();
const PORT = process.env.PORT || 4000;

// * Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/", (req, res) => {
    return res.send("Hi Everyone.");
});
  
// * routes file
import userRouter from "./routes/userRoutes.js"


app.use("/api/user", userRouter);



app.listen(PORT, () => console.log(`Server is running on PORT ${PORT}`));


/*
npx prisma migrate dev --name create_user_schema
 */