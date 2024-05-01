const Categories = require("../models/CategoriesModel");
const AppError = require("../utils/AppError");
const catchAsync = require("../utils/catchAsync");

// ************ PUBLIC CONTROLLER ************

// @desc    Get all categories
// @route   GET /api/v1/categories
// @access  Public

exports.getCategories = catchAsync(async (req, res, next) => {
  // get categories
  const categories = await Categories.find({}, { __v: 0 });

  // check if no category found
  if (categories.length === 0) {
    return next(new AppError("No category found", 404));
  }

  res.status(200).json({
    success: "success",
    totalCategories: categories.length,
    data: categories,
  });
});
