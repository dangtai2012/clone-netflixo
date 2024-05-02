const { sendMail } = require("../services/sendMail");
const { generateToken } = require("./tokenService");

exports.sendVerificationEmail = async (user, req) => {
  const verificationToken = generateToken(user._id);
  const verificationLink = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/users/verify/${verificationToken}`;

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

  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/users/reset-password/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

  await sendMail({
    email: user.email,
    subject: "Your password reset token (valid for 10 min)",
    message,
  });
};
