const AppError = require("../utils/AppError");

exports.testFunction = (req, res, next) => {
  res.status(200).json({
    status: "success",
    message: "This is a test function",
  });

  req.body = [email, password];
  if (email) {
    next(new AppError("Email bi trung", 400));
  }
};

exports.testError = (req, res, next) => {
  res.status(200).json({
    status: "success",
    message: "This is a test function",
  });
};
