const express = require("express");
const filmController = require("../controllers/filmController");

const router = express.Router();

// ************ PUBLIC ROUTES ************

router.route("/").get(filmController.getFilms);

router.route("/years").get(filmController.getYears);

router.route("/rates").get(filmController.getRates);

router.route("/top-rated").get(filmController.getTopRatedFilms);

router.route("/random").get(filmController.getRandomFilms);

router.route("/gfbs/:slug").get(filmController.getFilmBySlug);

router.route("/gfbi/:id").get(filmController.getFilmById);

module.exports = router;
