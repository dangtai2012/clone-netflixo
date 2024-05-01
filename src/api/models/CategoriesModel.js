const mongoose = require("mongoose");

const categoriesSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "A category must have a name"],
  },

  slug: String,
});

const Categories = mongoose.model("categories", categoriesSchema);
module.exports = Categories;
