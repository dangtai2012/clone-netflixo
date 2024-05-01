const express = require("express");
const categoryController = require("../controllers/categoriesController");

const router = express.Router();

// ************ PUBLIC ROUTES ************

router.route("/").get(categoryController.getCategories);

module.exports = router;
