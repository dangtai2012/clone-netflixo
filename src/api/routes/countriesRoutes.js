const express = require("express");
const countriesController = require("../controllers/countriesController");

const router = express.Router();

// ************ PUBLIC ROUTES ************

router.route("/").get(countriesController.getCountries);

module.exports = router;
