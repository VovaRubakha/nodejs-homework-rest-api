const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");
const { nanoid } = require("nanoid");
require("dotenv").config();

const { SECRET_KEY } = process.env;

const User = require("../../models/user");

const router = express.Router();
const { createError, sendMail } = require("../../helpers");
const { authorize, upload } = require("../../middlewares");

const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;

const userRegisterSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().required(),
});

const userLoginSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
});

const verifyEmailSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
});

//avatarPath
const avatarsDir = path.join(__dirname, "../../", "public", "avatars");

//signup
router.post("/register", async (req, res, next) => {
  try {
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }
    const { email, password, name } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      throw createError(409, "email already exist");
    }
    const hashPassword = await bcrypt.hash(password, 10);
    //add gravatar
    const avatarURL = gravatar.url(email);
    //add verification Token
    const verificationToken = nanoid();

    const result = await User.create({
      email,
      password: hashPassword,
      name,
      avatarURL,
      verificationToken,
    });

    //verification message
    const mail = {
      to: email,
      subject: "Підтвердження реєстраціїї на сервері",
      html: `<a target="_blank" href="http://localhost:3000/api/auth/${verificationToken}">Натисніть для підтвердження реєстрації</a>`,
    };
    await sendMail(mail);

    res.status(201).json({
      name: result.name,
      email: result.email,
    });
  } catch (error) {
    next(error);
  }
});

//verification endpoint
router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });
    if (!user) {
      throw createError(404);
    }

    await User.findByIdAndUpdate(user._id, {
      verificationToken: "",
      verify: true,
    });
    res.json({
      message: "Verification successful",
    });
  } catch (error) {
    next(error);
  }
});

router.post("/verify", async (req, res, next) => {
  try {
    const { error } = verifyEmailSchema.validate(req.body);
    if (error) {
      throw createError(400);
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw createError(404);
    }
    if (user.verify) {
      throw createError(400, "Verification has already been passed");
    }

    const mail = {
      to: email,
      subject: "Підтвердження реєстраціїї на сервері",
      html: `<a target="_blank" href="http://localhost:3000/api/users/${user.verificationToken}">Натисніть для підтвердження реєстрації</a>`,
    };
    await sendMail(mail);
    res.json({
      message: "Verification email sent",
    });
  } catch (error) {
    next(error);
  }
});

// signin
router.post("/login", async (req, res, next) => {
  try {
    const { error } = userLoginSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw createError(401, "Email wrong");
    }
    if (!user.verify) {
      throw createError(401, "Email not verified");
    }

    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) {
      throw createError(401, "Password wrong");
    }

    //const passwordCompare = await bcrypt.compare(password, user.password);

    // if (!user || !passwordCompare) {
    //   throw createError(401, "Email or password is wrong");
    // }
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
    await User.findByIdAndUpdate(user._id, { token });
    res.json({
      token,
    });
  } catch (error) {
    next(error);
  }
});

//logout

router.get("/logout", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    const user = await User.findById(_id);
    if (!user) {
      throw createError(401, "Not authorized");
    }
    await User.findByIdAndUpdate(_id, { token: "" });

    res.status(204).json({
      message: "Logout Success",
    });
  } catch (error) {
    next(error);
  }
});

//current
router.get("/current", authorize, async (req, res) => {
  const { email } = req.user;
  res.status(200).json({ email });
});

//patchUserAvatar
router.patch(
  "/avatars",
  authorize,
  upload.single("avatar"),
  async (req, res, next) => {
    try {
      const { _id } = req.user;
      const { path: tempDir, originalname } = req.file;

      const [extention] = originalname.split(".").reverse();
      const newAvatar = `${_id}.${extention}`;
      const uploadDir = path.join(avatarsDir, newAvatar);

      await fs.rename(tempDir, uploadDir);
      const avatarURL = path.join("avatars", newAvatar);
      //addJimp

      Jimp.read(uploadDir, (err, lenna) => {
        if (err) throw err;
        lenna.resize(250, 250).write(uploadDir);
      });

      await User.findByIdAndUpdate(_id, { avatarURL });
      res.json({ avatarURL });
    } catch (error) {
      await fs.unlink(req.file.path);
      next(error);
    }
  }
);

module.exports = router;
