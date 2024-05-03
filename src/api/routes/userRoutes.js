const express = require("express");
const userController = require("../controllers/userController");

const router = express.Router();

// ************ PUBLIC ROUTES ************
router.route("/register").post(userController.registerUser);
router.route("/login").post(userController.loginUser);
router.route("/logout").get(userController.logout);
router.route("/verify/:token").get(userController.verifyUser);
router.route("/forgot-password").post(userController.forgotPassword);
router.route("/reset-password/:token").get(userController.resetPassword);

// ************ PROTECTED ROUTES ************
router.route("/me").get(userController.protect, userController.getUser);

router
  .route("/update-password")
  .patch(userController.protect, userController.updatePassword);

module.exports = router;
