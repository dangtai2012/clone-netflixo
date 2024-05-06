const { sendMail } = require("../services/sendMail");
const { generateToken } = require("./tokenService");
const AppError = require("../utils/AppError");
const catchAsync = require("../utils/catchAsync");

exports.sendVerificationEmail = async (user, req) => {
  const verificationToken = generateToken(user._id);

  const verificationLink = `https://clone-netflixo.onrender.com/api/v1/users/verify/${verificationToken}`;

  const message = `<h2 style="color: #333;">Welcome to Our Website!</h2>
                    <p>Dear ${user.first_name} ${user.last_name},</p>
                    <p>Thank you for registering at our website. Please click the button below to verify your email address:</p>
                    <a href=${verificationLink} style="background-color: #4CAF50; color: white; padding: 15px 32px; text-decoration: none; display: inline-block;">Verify Email</a>
                    <p>If you did not register for our website, please ignore this email.</p>
                    <p>Best regards,</p>
                    <p>Netflix Team</p>`;
  await sendMail({
    email: user.email,
    subject: "Email verification",
    message,
  });

  return verificationToken;
};

exports.sendPasswordResetEmail = async (user, req) => {
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `https://clone-netflixo.onrender.com/api/v1/users/resetPassword/${resetToken}`;

  const message = `<h2 style="color: #333;">Password Reset</h2>
                    <p>Dear ${user.first_name} ${user.last_name},</p>
                    <p>Forgot your password? Click the button below to reset it:</p>
                    <a href=${resetURL} style="background-color: #4CAF50; color: white; padding: 15px 32px; text-decoration: none; display: inline-block;">Reset Password</a>
                    <p>If you didn't forget your password, please ignore this email.</p>
                    <p>Best regards,</p>
                    <p>Netflix Team</p>`;
  await sendMail({
    email: user.email,
    subject: "Password reset",
    message,
  });
};
