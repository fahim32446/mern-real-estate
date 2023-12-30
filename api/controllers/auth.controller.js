import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';
import { errorHandler } from '../utils/error.js';
import tokens from '../models/token.model.js';
import nodemailer from 'nodemailer';

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;
  const hashedPassword = bcryptjs.hashSync(password, 10);
  const newUser = new User({ username, email, password: hashedPassword });
  try {
    await newUser.save();
    res.status(201).json('User created successfully!');
  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const validUser = await User.findOne({ email });

    if (!validUser) return next(errorHandler(404, 'User not found!'));

    const validPassword = bcryptjs.compareSync(password, validUser.password);

    if (!validPassword) return next(errorHandler(401, 'Wrong credentials!'));

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);

    const { password: pass, ...rest } = validUser._doc;

    res
      .cookie('access_token', token, { httpOnly: true })
      .status(200)
      .json(rest);
  } catch (error) {
    next(error);
  }
};

export const google = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      const { password: pass, ...rest } = user._doc;
      res
        .cookie('access_token', token, { httpOnly: true })
        .status(200)
        .json(rest);
    } else {
      const generatedPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8);
      const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);
      const newUser = new User({
        username:
          req.body.name.split(' ').join('').toLowerCase() +
          Math.random().toString(36).slice(-4),
        email: req.body.email,
        password: hashedPassword,
        avatar: req.body.photo,
      });
      await newUser.save();
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
      const { password: pass, ...rest } = newUser._doc;
      res
        .cookie('access_token', token, { httpOnly: true })
        .status(200)
        .json(rest);
    }
  } catch (error) {
    next(error);
  }
};

export const signOut = async (req, res, next) => {
  try {
    res.clearCookie('access_token');
    res.status(200).json('User has been logged out!');
  } catch (error) {
    next(error);
  }
};

export const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return next(errorHandler(404, 'User not found!'));
    }
    const resetToken = Math.floor(100000 + Math.random() * 900000);
    const resetTokenExpiry = Date.now() + 3600000; // Token expiry in 1 hour

    // Save the reset OTP to the database
    await tokens.create({
      user: user._id,
      resetToken,
      resetTokenExpiry,
    });

    // Send password reset email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      host: 'smtp.gmail.com',
      port: '587',
      auth: {
        user: process.env.SENDER_EMAIL,
        pass: process.env.SENDER_EMAIL_APP_PASS,
      },
    });

    const mailOptions = {
      from: user.email,
      to: email,
      subject: 'Password Reset',
      text: `Please provide this code for reset your password : ${resetToken}`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({
      success: true,
      message: 'Password reset email sent',
      statusCode: 200,
    });
  } catch (error) {
    next(error);
  }
};

export const verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return next(errorHandler(404, 'User not found!'));
    }

    const token = await tokens.findOne({ user: user._id, resetToken: otp });

    if (!token || token.resetTokenExpiry < Date.now()) {
      return next(errorHandler(404, 'Invalid or expired OTP'));
    }

    const secret = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '5m',
    });

    await token.deleteOne();

    return res.json({
      success: true,
      statusCode: 200,
      message: 'OTP verified successfully',
      token: secret,
    });
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  const { email, token, password } = req.body;

  try {
    if (!token) {
      return next(errorHandler(401, 'Unauthorized'));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded || !decoded.id) {
      return next(errorHandler(401, 'Invalid or expired token'));
    }

    const user = await User.findById(decoded.id);

    if (!user) {
      return next(errorHandler(404, 'User not found'));
    }

    const hashedPassword = bcryptjs.hashSync(password, 10);
    user.password = hashedPassword;
    await user.save();

    return res.json({
      success: true,
      statusCode: 200,
      message: 'Password reset successfully',
    });
  } catch (error) {
    next(error);
  }
};
