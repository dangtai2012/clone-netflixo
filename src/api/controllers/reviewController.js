const Review = require("../models/ReviewModel");
const Film = require("../models/FilmModel");
const AppError = require("../utils/AppError");
const catchAsync = require("../utils/catchAsync");

// ************ PUBLIC CONTROLLER ************

// @desc    Get all reviews
// @route   GET /api/v1/reviews
// @route   GET /api/v1/films/:filmId/reviews
// @access  Public

exports.getAllReviews = catchAsync(async (req, res, next) => {
  let filter = {};
  if (req.params.filmId) filter = { film: req.params.filmId };

  const reviews = await Review.find(filter);
  res.status(200).json({
    status: "success",
    results: reviews.length,
    data: {
      reviews,
    },
  });
});

// @desc    Create a review
// @route   POST /api/v1/reviews
// @route   POST /api/v1/films/:filmId/reviews
// @access  Private

exports.createReview = catchAsync(async (req, res, next) => {
  const alreadyReviewed = await Review.findOne({
    film: req.params.filmId,
    user: req.user.id,
  });

  if (alreadyReviewed) {
    return next(new AppError("You have already reviewed this film", 400));
  }

  // Allow nested routes
  if (!req.body.film) req.body.film = req.params.filmId;
  if (!req.body.user) req.body.user = req.user.id;

  await Review.create(req.body).then(async (newReview) => {
    const stats = await Review.aggregate([
      {
        $match: { film: newReview.film },
      },
      {
        $group: {
          _id: "$film",
          nRating: { $sum: 1 },
          avgRating: { $avg: "$rating" },
        },
      },
    ]);

    await Film.findByIdAndUpdate(req.params.filmId, {
      rate: stats[0].avgRating,
    });

    res.status(201).json({
      status: "success",
      data: {
        review: newReview,
      },
    });
  });
});

// @desc    Update a review
// @route   PATCH /api/v1/reviews/:id
// @access  Private

exports.updateReview = catchAsync(async (req, res, next) => {
  const review = await Review.findById(req.params.reviewId);

  if (!review) {
    return next(new AppError("No review found with that ID", 404));
  }

  if (review.user._id.toString() !== req.user.id) {
    return next(new AppError("You are not allowed to update this review", 401));
  }

  await Review.findByIdAndUpdate(req.params.reviewId, req.body, {
    new: true,
    runValidators: true,
  }).then(async (updatedReview) => {
    const stats = await Review.aggregate([
      {
        $match: { film: updatedReview.film },
      },
      {
        $group: {
          _id: "$film",
          nRating: { $sum: 1 },
          avgRating: { $avg: "$rating" },
        },
      },
    ]);

    await Film.findByIdAndUpdate(updatedReview.film, {
      rate: stats[0].avgRating,
    });

    res.status(200).json({
      status: "success",
      data: {
        review: updatedReview,
      },
    });
  });
});

// @desc    Delete a review
// @route   DELETE /api/v1/reviews/:id
// @access  Private

exports.deleteReview = catchAsync(async (req, res, next) => {
  const review = await Review.findById(req.params.reviewId);

  if (!review) {
    return next(new AppError("No review found with that ID", 404));
  }

  if (review.user._id.toString() !== req.user.id) {
    return next(new AppError("You are not allowed to delete this review", 401));
  }

  await Review.findByIdAndDelete(req.params.reviewId).then(async () => {
    const stats = await Review.aggregate([
      {
        $match: { film: review.film },
      },
      {
        $group: {
          _id: "$film",
          nRating: { $sum: 1 },
          avgRating: { $avg: "$rating" },
        },
      },
    ]);

    await Film.findByIdAndUpdate(review.film, {
      rate: stats[0].avgRating,
    });

    res.status(200).json({
      status: "success",
      data: null,
    });
  });
});
