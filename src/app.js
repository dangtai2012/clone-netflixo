const express = require("express");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");

//: ******* ROUTE HANDLERS *******
const AppError = require("./api/utils/AppError");
const globalErrorHandler = require("./api/controllers/errorController");
const filmRouter = require("./api/routes/filmRoutes");
const categoriesRouter = require("./api/routes/categoriesRoutes");
const countriesRouter = require("./api/routes/countriesRoutes");
const testRouter = require("./api/routes/testRoutes");

//: ******* START EXPRESS APP *******
const app = express();

//: >>>>>>> START GLOBAL MIDDLEWARE >>>>>>>
// 1) cors
app.use(cors());

// 2) Serving static files
app.use(express.static(path.join(__dirname, "api/public")));

// 3) helmet
app.use(helmet());

// 4) Development logging
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// 5) Limit requests from same API
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour!",
});
app.use("/api", limiter);

// 6) Body parser, reading data from body into req.body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 7) Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// 8) Data sanitization against XSS
app.use(xss());

//: >>>>>>> END GLOBAL MIDDLEWARE >>>>>>>

//: ******* ROUTES *******
app.use("/api/v1/test", testRouter);
app.use("/api/v1/films", filmRouter);
app.use("/api/v1/categories", categoriesRouter);
app.use("/api/v1/countries", countriesRouter);

//: ******* ERROR HANDLING *******
// 1) Handle unhandled routes
app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handling middleware
app.use(globalErrorHandler);

module.exports = app;
