import nodemailer from 'nodemailer';

export async function sendVerificationEmail(email, username, verifyCode) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail', // You can replace this with another service if necessary
      auth: {
        user: process.env.EMAIL_USER, // your email
        pass: process.env.EMAIL_PASS, // your email password or app-specific password
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER, // sender address
      to: email, // recipient email
      subject: 'Account Verification Code', // Subject line
      text: `Hello ${username},\n\nYour verification code is: ${verifyCode}\n\nPlease use this code to verify your account.`, // plain text body
    };

    const info = await transporter.sendMail(mailOptions);

    return {
      success: true,
      message: `Email sent: ${info.response}`,
    };
  } catch (error) {
    console.error("Error sending email:", error);
    return {
      success: false,
      message: "Failed to send verification email",
    };
  }
}
