const mongoose = require("mongoose");

const episodeSchema = new mongoose.Schema({
  film_id: {
    type: mongoose.Schema.ObjectId,
    ref: "films",
    required: [true, "Film id is required"],
  },

  server_name: String,

  server_data: [
    {
      name: {
        type: String,
        required: [true, "Name is required"],
      },

      slug: {
        type: String,
        required: [true, "Slug is required"],
      },

      filename: {
        type: String,
        required: [true, "Filename is required"],
      },

      link_embed: {
        type: String,
        required: [true, "Link embed is required"],
      },

      link_m3u8: {
        type: String,
        required: [true, "Link m3u8 is required"],
      },
    },
  ],
});

const Episode = mongoose.model("episodes", episodeSchema);
module.exports = Episode;
