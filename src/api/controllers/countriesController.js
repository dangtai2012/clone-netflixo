const Countries = require("../models/CountriesModel");
const AppError = require("../utils/AppError");
const catchAsync = require("../utils/catchAsync");

// ************ PUBLIC CONTROLLER ************
// @desc    Get all countries
// @route   GET /api/v1/countries
// @access  Public

exports.getCountries = catchAsync(async (req, res, next) => {
  // get countries
  const countries = await Countries.find({}, { __v: 0 });

  // check if no country found
  if (countries.length === 0) {
    return next(new AppError("No country found", 404));
  }

  res.status(200).json({
    success: "success",
    totalCountries: countries.length,
    data: countries,
  });
});
