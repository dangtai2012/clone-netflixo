module.exports = (asfn) => {
  return (req, res, next) => {
    asfn(req, res, next).catch(next);
  };
};
