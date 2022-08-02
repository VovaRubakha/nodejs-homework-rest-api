const express = require("express");
const Joi = require("joi");

const User = require("../../models/user");

const router = express.Router();
const createError = require("../../helpers/createError");

const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;

const userRegisterSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().required(),
});

//signup
router.post("/register", async (req, res, next) => {
  try {
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      throw createError(400);
    }
    const { email, password, name } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      throw createError(409, "email already exist");
    }
    const result = await User.create({ email, password, name });
    res.status(201).json({
      name: result.name,
      email: result.email,
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
