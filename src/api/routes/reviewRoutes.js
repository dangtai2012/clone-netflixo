const express = require("express");
const reviewController = require("../controllers/reviewController");
const userController = require("../controllers/userController");

const router = express.Router({ mergeParams: true });

router
  .route("/")
  .get(reviewController.getAllReviews)
  .post(
    userController.protect,
    userController.restrictTo("user"),
    reviewController.createReview
  );

router
  .route("/:reviewId")
  .patch(
    userController.protect,
    userController.restrictTo("user"),
    reviewController.updateReview
  )
  .delete(
    userController.protect,
    userController.restrictTo("user"),
    reviewController.deleteReview
  );

module.exports = router;
