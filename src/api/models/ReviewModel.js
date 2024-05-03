const mongoose = require("mongoose");
const { create } = require("./UserModel");

const reviewSchema = new mongoose.Schema(
  {
    rating: {
      type: Number,
      required: [true, "Rating is required"],
      min: 1,
      max: 5,
    },

    comment: {
      type: String,
      required: [true, "Comment can not be empty!"],
    },

    film: {
      type: mongoose.Schema.ObjectId,
      ref: "films",
      required: [true, "Review must belong to a film"],
    },

    user: {
      type: mongoose.Schema.ObjectId,
      ref: "users",
      required: [true, "Review must belong to a user"],
    },
  },

  {
    timestamps: true,
  }
);

reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: "user",
    select: "first_name last_name image_url",
  });

  next();
});

const Review = mongoose.model("reviews", reviewSchema);
module.exports = Review;
