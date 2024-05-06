const express = require("express");
const userController = require("../controllers/userController");
const upload = require("../services/cloudinaryService");

const router = express.Router();

// ************ PUBLIC ROUTES ************
router.route("/register").post(userController.registerUser);
router.route("/login").post(userController.loginUser);
router.route("/logout").get(userController.logout);
router.route("/verify/:token").get(userController.verifyUser);
router.route("/forgot-password").post(userController.forgotPassword);
router.route("/reset-password/:token").get(userController.resetPassword);
router
  .route("/update-password")
  .patch(userController.protect, userController.updatePassword);

// ************ PROTECTED ROUTES ************
router.route("/me").get(userController.protect, userController.getUser);
router
  .route("/update-me")
  .patch(
    upload.single("image_url"),
    userController.protect,
    userController.updateUser
  );

router
  .route("/favorite/:filmId")
  .patch(userController.protect, userController.addToFavorites);

router
  .route("/favorites")
  .get(userController.protect, userController.getFavorites);
router
  .route("/favorites/:filmId")
  .delete(userController.protect, userController.removeFromFavorites);

module.exports = router;
