const AppError = require("../utils/AppError");
const catchAsync = require("../utils/catchAsync");
const User = require("../models/UserModel");
const { generateToken, verifyToken } = require("../services/tokenService");
const {
  sendVerificationEmail,
  sendPasswordResetEmail,
} = require("../services/mailService");
const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");

// @desc    Register a new user
// @route   POST /api/v1/users/register
// @access  Public

exports.registerUser = catchAsync(async (req, res, next) => {
  const requiredFields = [
    "first_name",
    "last_name",
    "email",
    "password",
    "passwordConfirm",
  ];
  const missingFields = requiredFields.filter((field) => !req.body[field]);
  if (missingFields.length) {
    return next(
      new AppError(`Missing required fields: ${missingFields.join(", ")}`, 400)
    );
  }
  const user = await User.create(req.body);
  const token = generateToken(user._id);
  const verificationToken = await sendVerificationEmail(user, req);
  await User.findByIdAndUpdate(user._id, { verificationToken });
  res.status(201).json({
    status: "success",
    message: "User registered successfully",
    data: {
      token,
    },
  });
});

// @desc    Log in a user
// @route   POST /api/v1/users/login
// @access  Public
exports.loginUser = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new AppError("Email and password are required", 400));
  }
  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }
  if (!user.isVerified) {
    return next(new AppError("User not verified", 401));
  }
  delete user._doc.password;
  const token = generateToken(user._id);

  res.cookie("jwt", token, {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  });

  res.status(200).json({
    status: "success",
    message: "User logged in successfully",
    data: {
      token,
    },
  });
});

// @desc    Log out a user
// @route   GET /api/v1/users/logout
// @access  Private
exports.logout = async (req, res) => {
  res.cookie("jwt", "loggedOut", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({
    status: "success",
  });
};

// @desc    Verify a user
// @route   GET /api/v1/users/verify/:token
// @access  Public

exports.verifyUser = catchAsync(async (req, res, next) => {
  const { token } = req.params;
  const user = await User.findOneAndUpdate(
    { verificationToken: token, isVerified: false },
    { isVerified: true, verificationToken: null },
    { new: true }
  );
  if (!user) {
    return next(new AppError("Invalid or expired token", 400));
  }
  res.status(200).json({
    status: "success",
    message: "User verified successfully",
    data: {
      user: {
        id: user._id,
        email: user.email,
        isVerified: user.isVerified,
      },
    },
  });
});

// @desc    Forgot password
// @route   POST /api/v1/users/forgotPassword
// @access  Public

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  try {
    await sendPasswordResetEmail(user, req);
    res.status(200).json({
      status: "success",
      message: "Password reset token sent to email",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(
      new AppError("There was an error sending the email. Try again later", 500)
    );
  }
});

// @desc    Reset password
// @route   GET /api/v1/users/resetPassword/:token
// @access  Public

exports.resetPassword = catchAsync(async (req, res, next) => {
  const token = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");
  const user = await User.findOne({
    passwordResetToken: token,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.passwordChangedAt = Date.now();
  await user.save();

  const newToken = generateToken(user._id);
  res.status(200).json({
    status: "success",
    message: "Password reset successful",
    data: {
      token: newToken,
    },
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  const testToken = req.headers.authorization;

  let token;
  if (testToken && testToken.startsWith("Bearer")) {
    token = testToken.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  if (!token) {
    return next(new AppError("You are not logged in", 401));
  }
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  if (!decoded) {
    return next(new AppError("Invalid token", 401));
  }
  const user = await User.findById(decoded.id);
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  if (user.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError("User recently changed password. Log in again", 401)
    );
  }
  req.user = user;
  next();
});

exports.restrictTo =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action", 403)
      );
    }

    next();
  };

// @desc    Update password
// @route   PATCH /api/v1/users/updatePassword
// @access  Private
exports.updatePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).select("+password");
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError("Incorrect password", 401));
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  const token = generateToken(user._id);
  res.cookie("jwt", token, {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  });
  res.status(200).json({
    status: "success",
    message: "Password updated successfully",
    data: {
      token,
    },
  });
});

// @desc    Get user
// @route   GET /api/v1/users/me
// @access  Private
exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

// @desc    Update user
// @route   PATCH /api/v1/users/updateMe
// @access  Private
exports.updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  const allowedFields = ["first_name", "last_name", "email"];
  Object.keys(req.body).forEach((field) => {
    if (allowedFields.includes(field)) {
      user[field] = req.body[field];
    }
  });
  if (req.file) {
    user.image_url = req.file.path;
  }
  await user.save();
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

// @desc    Add to favorites
// @route   PATCH /api/v1/users/favorites/:filmId
// @access  Private
exports.addToFavorites = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  if (user.favorite.includes(req.params.filmId)) {
    return next(new AppError("Film already in favorites", 400));
  }
  user.favorite.push(req.params.filmId);
  await user.save();
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

exports.getFavorites = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).populate("favorite");
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

exports.removeFromFavorites = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(new AppError("User not found", 404));
  }
  if (!user.favorite.includes(req.params.filmId)) {
    return next(new AppError("Film not in favorites", 400));
  }
  user.favorite = user.favorite.filter((film) => film != req.params.filmId);
  await user.save();
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});
