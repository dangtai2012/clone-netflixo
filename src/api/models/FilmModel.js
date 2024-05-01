const mongoose = require("mongoose");
const slugify = require("slugify");

const filmSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "A film must have a name"],
      trim: true,
    },

    origin_name: {
      type: String,
      required: [true, "A film must have a name"],
      trim: true,
    },

    slug: String,

    description: {
      type: String,
    },

    thumb_url: {
      type: String,
      required: [true, "A film must have a thumbnail"],
    },

    poster_url: {
      type: String,
      required: [true, "A film must have a poster"],
    },

    type: {
      type: String,
      required: [true, "A film must have a type"],
    },

    quality: {
      type: String,
      required: [true, "A film must have a quality"],
    },

    year: {
      type: Number,
      required: [true, "A film must have a year"],
    },

    time: {
      type: String,
      required: [true, "A film must have a time"],
    },

    language: {
      type: String,
      required: [true, "A film must have a language"],
    },

    trailer_url: {
      type: String,
    },

    episode_current: {
      type: String,
    },

    episode_total: {
      type: String,
    },

    rate: {
      type: Number,
      default: 0,
    },

    countries: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "countries",
      },
    ],

    categories: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "categories",
      },
    ],

    casts: [
      {
        _id: false,
        name: {
          type: String,
        },
        image_url: {
          type: String,
        },
      },
    ],
  },
  {
    toJSON: {
      virtuals: true,
      transform: function (doc, ret) {
        delete ret.id;
      },
    },
    toObject: { virtuals: true },
  }
);

// Virtual populate
filmSchema.virtual("episodes", {
  ref: "episodes",
  foreignField: "_id",
  localField: "film_id",
});

const Film = mongoose.model("films", filmSchema);
module.exports = Film;
