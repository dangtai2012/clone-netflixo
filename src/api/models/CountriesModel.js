const mongoose = require("mongoose");

const countriesSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "A country must have a name"],
  },

  slug: String,
});

const Countries = mongoose.model("countries", countriesSchema);
module.exports = Countries;
